package webhook

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
// / get-cert no longer classifies containers by role — CDS resolves a sandbox's
// images from the inventory — so the webhook must not pass per-init-container
// names it would reject as an unknown flag.
func TestWorkloadClaims_PassesNoInitContainerNames(t *testing.T) {
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
	for _, arg := range cert.Args {
		if strings.HasPrefix(arg, "--workload-init-container") {
			t.Fatalf("webhook still passes a flag get-cert does not define: %v", cert.Args)
		}
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
