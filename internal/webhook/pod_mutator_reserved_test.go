package webhook

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TestPreDeclaredReservedMountIsForcedReadOnly covers a pod that declares its
// own mount of a reserved volume with readOnly omitted (defaulting to false).
// Matching on the name and skipping would leave that writable mount in place,
// handing the workload write access to the shared secrets directory and to the
// sidecar-managed leaf key — the invariant secretContainer depends on.
func TestPreDeclaredReservedMountIsForcedReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		volume string
	}{
		{"secrets", secretsVolumeName},
		{"certs", defaultCertVolumeName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
				Name:      tc.volume,
				MountPath: "/attacker/chosen/path",
			}}
			pod.Spec.Volumes = []corev1.Volume{{
				Name: tc.volume,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
				},
			}}

			mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

			m := containerMount(&pod.Spec.Containers[0], tc.volume)
			if m == nil {
				t.Fatalf("workload container lost its %q mount", tc.volume)
			}
			if !m.ReadOnly {
				t.Fatalf("pre-declared %q mount stayed writable: %+v", tc.volume, *m)
			}
			// Only the write bit is coerced; the pod keeps its mount path.
			if m.MountPath != "/attacker/chosen/path" {
				t.Fatalf("MountPath = %q, want the pod's own path", m.MountPath)
			}
		})
	}
}

// The fetcher is the one container that must keep write access. It is appended
// after mountAll runs and rebuilt by injectInitContainers on every call, so a
// reinvocation over an already-injected pod must not leave it read-only.
func TestFetcherKeepsWriteAccessAcrossReinvocation(t *testing.T) {
	pod := podWithApp()
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

	fetcher := containerNamed(pod, reservedSecretContainerName)
	if fetcher == nil {
		t.Fatal("fetcher not injected")
	}
	m := containerMount(fetcher, secretsVolumeName)
	if m == nil {
		t.Fatal("fetcher lost its secrets mount")
	}
	if m.ReadOnly {
		t.Fatal("fetcher's secrets mount went read-only; it could no longer write released values")
	}

	// The workload's mount stays read-only across the same reinvocation.
	if wm := containerMount(&pod.Spec.Containers[0], secretsVolumeName); wm == nil || !wm.ReadOnly {
		t.Fatalf("workload secrets mount = %+v, want a read-only mount", wm)
	}
}

// TestEphemeralGuardIgnoresAnnotationRewrite is the annotation-rewrite bypass:
// annotations stay mutable on a running pod, so pointing AnnotationCertVolume
// at a decoy must not free the volume that actually holds the leaf key.
func TestEphemeralGuardIgnoresAnnotationRewrite(t *testing.T) {
	pod := podWithApp()
	pod.Annotations = map[string]string{AnnotationCertVolume: "my-certs"}
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Cert:       certSpec{Volume: "my-certs"},
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
	}, secretsConfig())

	// The attacker rewrites the annotation on the running pod, then attaches an
	// ephemeral container mounting the real cert volume.
	pod.Annotations[AnnotationCertVolume] = "decoy"
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:         "debugger",
			VolumeMounts: []corev1.VolumeMount{{Name: "my-certs", MountPath: "/x"}},
		},
	}}

	if err := rejectEphemeralReservedMounts(pod); err == nil {
		t.Fatal("annotation rewrite let an ephemeral container mount the real cert volume")
	}

	// The secrets volume has a fixed name, so it is reserved either way.
	pod.Spec.EphemeralContainers[0].VolumeMounts = []corev1.VolumeMount{{Name: secretsVolumeName, MountPath: "/x"}}
	if err := rejectEphemeralReservedMounts(pod); err == nil {
		t.Fatal("ephemeral container mounted the released secrets")
	}

	// A genuinely unrelated volume is still fine.
	pod.Spec.EphemeralContainers[0].VolumeMounts = []corev1.VolumeMount{{Name: "scratch", MountPath: "/x"}}
	if err := rejectEphemeralReservedMounts(pod); err != nil {
		t.Fatalf("rejected a harmless ephemeral container: %v", err)
	}
}

func TestReservedVolumeNamesCoversSidecarMounts(t *testing.T) {
	pod := podWithApp()
	pod.Spec.InitContainers = []corev1.Container{
		{Name: reservedCertContainerName, VolumeMounts: []corev1.VolumeMount{
			{Name: "my-certs"}, {Name: workloadClaimsVolumeName},
		}},
		{Name: "user-init", VolumeMounts: []corev1.VolumeMount{{Name: "user-scratch"}}},
	}

	reserved := reservedVolumeNames(pod)
	for _, want := range []string{secretsVolumeName, defaultCertVolumeName, "my-certs", workloadClaimsVolumeName} {
		if !reserved[want] {
			t.Errorf("%q not reserved", want)
		}
	}
	// A non-c8s init container's mounts are the pod's own business.
	if reserved["user-scratch"] {
		t.Error("a user init container's volume was reserved")
	}
}

func handleSecretsPod(t *testing.T, cfg Config) admission.Response {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationSecrets:  "DB=/api/db",
		}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	m := &podMutator{decoder: admission.NewDecoder(scheme), cfg: cfg}
	return m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "tenant",
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
}

// TestHandleRejectsSecretsWithoutAnyInventory covers the shape no fetcher can
// serve: no mounted socket and not the kata guest, so there is no inventory to
// redeem a sandbox token at. Injecting anyway produces a Running pod whose
// fetcher CrashLoops while the workload blocks forever on a file that never
// lands — fail at admission instead.
func TestHandleRejectsSecretsWithoutAnyInventory(t *testing.T) {
	cfg := secretsConfig() // neither WorkloadClaimsHostDir nor WorkloadClaimsGuest

	resp := handleSecretsPod(t, cfg)
	if resp.Allowed {
		t.Fatal("admitted a secrets pod the fetcher could never serve")
	}
	if msg := resp.Result.Message; !strings.Contains(msg, AnnotationSecrets) {
		t.Fatalf("denial %q does not name the offending annotation", msg)
	}
}

// The same pod is admitted once the operator has the inventory socket, so the
// guard rejects only the shape that cannot work.
func TestHandleAdmitsSecretsWithInventorySocket(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/run/c8s/nri"

	if resp := handleSecretsPod(t, cfg); !resp.Allowed {
		t.Fatalf("Handle denied a serviceable secrets pod: %v", resp.Result)
	}
}

// Under kata the inventory is policy-monitor on guest loopback, so a secrets
// pod is serviceable with nothing mounted.
func TestHandleAdmitsSecretsUnderKataGuest(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsGuest = true

	if resp := handleSecretsPod(t, cfg); !resp.Allowed {
		t.Fatalf("Handle denied a secrets pod the guest inventory can serve: %v", resp.Result)
	}
}

// The fetcher must be told to use the guest endpoint, not merely admitted: the
// node-CVM socket it would otherwise dial cannot exist in a kata guest.
func TestSecretContainerSelectsGuestInventoryUnderKata(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsGuest = true
	inj := &injection{Secrets: secretsSpec{Specs: []string{"DB=/api/db"}, Dir: "/run/c8s/secrets"}}

	args := secretContainer(inj, cfg).Args
	if !slices.Contains(args, "--workload-claims-guest") {
		t.Fatalf("get-secret args %v omit --workload-claims-guest under kata", args)
	}
}

// And must not be told to under node-CVM, where the guest port serves nothing.
func TestSecretContainerKeepsSocketInventoryOnNodeCVM(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/run/c8s/nri"
	inj := &injection{Secrets: secretsSpec{Specs: []string{"DB=/api/db"}, Dir: "/run/c8s/secrets"}}

	args := secretContainer(inj, cfg).Args
	if slices.Contains(args, "--workload-claims-guest") {
		t.Fatalf("get-secret args %v select the guest inventory on node-CVM", args)
	}
}
