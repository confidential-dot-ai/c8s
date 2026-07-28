package webhook

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The inventory excludes the webhook-injected sidecars from the workload digest
// by name (workloadclaims.ReservedInjectedNames). Those names are defined
// independently from the webhook's own reserved-name constants, and nothing
// couples them: a rename here that misses the other side would silently let an
// injected image pollute a pod's workload claim. Guard the coupling.
func TestReservedInjectedNamesMatchWebhookConstants(t *testing.T) {
	want := map[string]bool{reservedCertContainerName: true, reservedCertWaitContainerName: true}
	if len(workloadclaims.ReservedInjectedNames) != len(want) {
		t.Fatalf("ReservedInjectedNames = %v, want the webhook's injected containers %v", workloadclaims.ReservedInjectedNames, want)
	}
	for _, name := range workloadclaims.ReservedInjectedNames {
		if !want[name] {
			t.Fatalf("ReservedInjectedNames has %q, not a webhook-injected container name", name)
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

// node-CVM (inventory + host dir): the webhook injects --workload-claims
// plus a read-only hostPath mount of the socket directory into the c8s-cert
// sidecar, so get-cert dials the mounted socket over its compiled path.
func TestWorkloadClaims_NodeCVMMountsInventorySocket(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		CDSURL:                "http://cds:8443",
		AttestationApiURL:     "http://as:8400",
		CertDir:               "/etc/c8s/certs",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})

	cert := pod.Spec.InitContainers[0]
	if !hasArg(cert.Args, "--workload-claims") {
		t.Fatalf("c8s-cert missing workload-claims flag: %v", cert.Args)
	}
	vol := findVolume(pod, workloadClaimsVolumeName)
	if vol == nil || vol.HostPath == nil || vol.HostPath.Path != "/var/run/nri-image-policy" {
		t.Fatalf("inventory hostPath volume missing or wrong: %#v", vol)
	}
	var mount *corev1.VolumeMount
	for i := range cert.VolumeMounts {
		if cert.VolumeMounts[i].Name == workloadClaimsVolumeName {
			mount = &cert.VolumeMounts[i]
		}
	}
	if mount == nil || !mount.ReadOnly || mount.MountPath != workloadclaims.SidecarSocketDir {
		t.Fatalf("inventory socket mount missing/writable/wrong path: %#v", mount)
	}
}

// The webhook passes the pod's own init-container names so get-cert can split
// the inventory's containers by role — and only the user's init containers, not
// the c8s-injected ones (which the inventory excludes anyway).
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
// neither the inventory flag nor a mount, so get-cert issues claim-free.
func TestWorkloadClaims_NoHostDirNoInventory(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "img",
		CDSURL:            "http://cds:8443",
		AttestationApiURL: "http://as:8400",
		CertDir:           "/etc/c8s/certs",
	})
	cert := pod.Spec.InitContainers[0]
	if hasArg(cert.Args, "--workload-claims") {
		t.Fatalf("unexpected workload-claims flag: %v", cert.Args)
	}
	if findVolume(pod, workloadClaimsVolumeName) != nil {
		t.Fatal("no inventory volume expected when disabled")
	}
	if pod.Spec.SecurityContext != nil {
		for _, g := range pod.Spec.SecurityContext.SupplementalGroups {
			if g == workloadclaims.InventorySocketGID {
				t.Fatal("inventory supplemental group injected without workload-claims enabled")
			}
		}
	}
}

// The inventory socket is group-owned (InventorySocketGID); the non-root sidecar can
// only reach it if the pod carries that supplemental group. Without it, connect
// fails closed and the pod hangs on its initial cert.
func TestWorkloadClaims_InjectsInventorySupplementalGroup(t *testing.T) {
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
		if g == workloadclaims.InventorySocketGID {
			found = true
		}
	}
	if !found {
		t.Fatalf("pod missing inventory supplemental group %d: %v", workloadclaims.InventorySocketGID, pod.Spec.SecurityContext.SupplementalGroups)
	}
}
