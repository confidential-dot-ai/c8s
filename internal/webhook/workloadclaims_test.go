package webhook

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The broker excludes the webhook-injected containers from the workload digest
// by name (workloadclaims.ReservedInjectedNames). Those names are defined
// independently from the webhook's own reserved-name list, and nothing couples
// them: a name added on one side but missed on the other would either let an
// injected image pollute a pod's workload claim, or let a digest-excluded name
// go unreserved and hide a workload image. Guard exact equality both ways.
func TestReservedInjectedNamesMatchWebhookConstants(t *testing.T) {
	want := map[string]bool{}
	for _, name := range reservedInjectedContainerNames() {
		want[name] = true
	}
	got := map[string]bool{}
	for _, name := range workloadclaims.ReservedInjectedNames {
		if got[name] {
			t.Fatalf("ReservedInjectedNames lists %q twice", name)
		}
		got[name] = true
		if !want[name] {
			t.Errorf("ReservedInjectedNames has %q, not a webhook-injected container name", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("webhook injects %q but ReservedInjectedNames does not exclude it from the digest", name)
		}
	}
}

func newInjectablePod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
}

func findVolume(pod *corev1.Pod, name string) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			return &pod.Spec.Volumes[i]
		}
	}
	return nil
}

// node-CVM (broker + host dir): the webhook injects --workload-claims-broker
// plus a read-only hostPath mount of the socket directory into the c8s-cert
// sidecar, so get-cert dials the mounted socket over its compiled path.
func TestWorkloadClaims_NodeCVMMountsBrokerSocket(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		CDSURL:                "http://cds:8443",
		AttestationApiURL:     "http://as:8400",
		CertDir:               "/etc/c8s/certs",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})

	cert := pod.Spec.InitContainers[0]
	if !hasArg(cert.Args, "--workload-claims-broker") {
		t.Fatalf("c8s-cert missing workload-claims-broker flag: %v", cert.Args)
	}
	vol := findVolume(pod, workloadClaimsVolumeName)
	if vol == nil || vol.HostPath == nil || vol.HostPath.Path != "/var/run/nri-image-policy" {
		t.Fatalf("broker hostPath volume missing or wrong: %#v", vol)
	}
	var mount *corev1.VolumeMount
	for i := range cert.VolumeMounts {
		if cert.VolumeMounts[i].Name == workloadClaimsVolumeName {
			mount = &cert.VolumeMounts[i]
		}
	}
	if mount == nil || !mount.ReadOnly || mount.MountPath != workloadclaims.SidecarSocketDir {
		t.Fatalf("broker socket mount missing/writable/wrong path: %#v", mount)
	}
}

// The webhook passes the pod's own init-container names so get-cert can split
// the broker's containers by role — and only the user's init containers, not
// the c8s-injected ones (which the broker excludes anyway).
func TestWorkloadClaims_PassesInitContainerNames(t *testing.T) {
	pod := newInjectablePod()
	pod.Spec.InitContainers = []corev1.Container{{Name: "setup"}, {Name: "migrate"}}
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		CDSURL:                "http://cds:8443",
		AttestationApiURL:     "http://as:8400",
		CertDir:               "/etc/c8s/certs",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})
	cert := pod.Spec.InitContainers[0]
	if cert.Name != "c8s-cert" {
		t.Fatalf("c8s-cert not first: %q", cert.Name)
	}
	for _, want := range []string{"--workload-init-container=setup", "--workload-init-container=migrate"} {
		if !hasArg(cert.Args, want) {
			t.Fatalf("c8s-cert missing %s: %v", want, cert.Args)
		}
	}
	// Its own injected init containers must NOT be listed.
	if hasArg(cert.Args, "--workload-init-container=c8s-cert") || hasArg(cert.Args, "--workload-init-container=c8s-cert-wait") {
		t.Fatalf("injected init containers leaked into the init-name list: %v", cert.Args)
	}
}

// No host dir (default, and the not-yet-wired kata path): the webhook injects
// neither the broker flag nor a mount, so get-cert issues claim-free.
func TestWorkloadClaims_NoHostDirNoBroker(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "img",
		CDSURL:            "http://cds:8443",
		AttestationApiURL: "http://as:8400",
		CertDir:           "/etc/c8s/certs",
	})
	cert := pod.Spec.InitContainers[0]
	if hasArg(cert.Args, "--workload-claims-broker") {
		t.Fatalf("unexpected workload-claims-broker flag: %v", cert.Args)
	}
	if findVolume(pod, workloadClaimsVolumeName) != nil {
		t.Fatal("no broker volume expected when disabled")
	}
	if pod.Spec.SecurityContext != nil {
		for _, g := range pod.Spec.SecurityContext.SupplementalGroups {
			if g == workloadclaims.BrokerSocketGID {
				t.Fatal("broker supplemental group injected without workload-claims enabled")
			}
		}
	}
}

// The broker socket is group-owned (BrokerSocketGID); the non-root sidecar can
// only reach it if the pod carries that supplemental group. Without it, connect
// fails closed and the pod hangs on its initial cert.
func TestWorkloadClaims_InjectsBrokerSupplementalGroup(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		CDSURL:                "http://cds:8443",
		AttestationApiURL:     "http://as:8400",
		CertDir:               "/etc/c8s/certs",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})
	if pod.Spec.SecurityContext == nil {
		t.Fatal("pod securityContext not set")
	}
	found := false
	for _, g := range pod.Spec.SecurityContext.SupplementalGroups {
		if g == workloadclaims.BrokerSocketGID {
			found = true
		}
	}
	if !found {
		t.Fatalf("pod missing broker supplemental group %d: %v", workloadclaims.BrokerSocketGID, pod.Spec.SecurityContext.SupplementalGroups)
	}
}
