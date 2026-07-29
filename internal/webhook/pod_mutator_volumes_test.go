package webhook

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volumed"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func mutateWithVolumes(t *testing.T, pod *corev1.Pod, specs []string, dir string) {
	t.Helper()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Volumes:    volumesSpec{Specs: specs, Dir: dir},
	}, secretsConfig())
}

func TestNoVolumesRequestedInjectsNothing(t *testing.T) {
	pod := podWithApp()
	mutateWithVolumes(t, pod, nil, "")
	if c := containerNamed(pod, reservedVolumeContainerName); c != nil {
		t.Fatal("the fetcher was injected without a volumes annotation")
	}
	for _, v := range pod.Spec.Volumes {
		if strings.HasPrefix(v.Name, volumed.KubeVolumePrefix) {
			t.Fatalf("volume %q was injected without a volumes annotation", v.Name)
		}
	}
}

// The fetcher runs alongside the workload, after the sidecar that writes the
// leaf it authenticates with.
func TestVolumeFetcherIsANativeSidecarAfterTheCertContainers(t *testing.T) {
	pod := podWithApp()
	mutateWithVolumes(t, pod, []string{"weights=/tenant-a/volumes/weights"}, "")

	c := containerNamed(pod, reservedVolumeContainerName)
	if c == nil {
		t.Fatalf("no fetcher injected; init containers = %v", initNames(pod))
	}
	if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Error("the fetcher is not a native sidecar; an init container would deadlock the pod it gates")
	}
	names := initNames(pod)
	cert := slices.Index(names, reservedCertContainerName)
	wait := slices.Index(names, reservedCertWaitContainerName)
	vol := slices.Index(names, reservedVolumeContainerName)
	if cert < 0 || wait < 0 || vol < 0 || cert > vol || wait > vol {
		t.Errorf("order = %v, want the fetcher after %s and %s", names, reservedCertContainerName, reservedCertWaitContainerName)
	}
	if !slices.Contains(c.Args, "get-volume") {
		t.Errorf("args = %v, want the get-volume entrypoint", c.Args)
	}
	if !slices.Contains(c.Args, "--volume=weights=/tenant-a/volumes/weights") {
		t.Errorf("args = %v, want the requested volume", c.Args)
	}
}

// The plaintext is read-only to the workload, and the node agent makes the
// mount from outside the pod — without HostToContainer the container keeps
// seeing the empty directory it started with.
func TestVolumeMountIsReadOnlyAndPropagated(t *testing.T) {
	pod := podWithApp()
	mutateWithVolumes(t, pod, []string{"weights=/tenant-a/volumes/weights"}, "")

	app := workloadContainer(t, pod, "app")
	m := mountNamed(app, volumed.KubeVolumeName("weights"))
	if m == nil {
		t.Fatalf("app has no volume mount; mounts = %v", mountNames(app))
	}
	if !m.ReadOnly {
		t.Error("the workload may write the decrypted volume")
	}
	if m.MountPropagation == nil || *m.MountPropagation != corev1.MountPropagationHostToContainer {
		t.Errorf("propagation = %v, want HostToContainer", m.MountPropagation)
	}
	if m.MountPath != "/run/c8s/volumes/weights" {
		t.Errorf("mount path = %q, want the default volume dir", m.MountPath)
	}
}

func TestVolumeDirOverride(t *testing.T) {
	pod := podWithApp()
	mutateWithVolumes(t, pod, []string{"weights=/tenant-a/volumes/weights"}, "/models")

	app := workloadContainer(t, pod, "app")
	if m := mountNamed(app, volumed.KubeVolumeName("weights")); m == nil || m.MountPath != "/models/weights" {
		t.Errorf("mount path = %v, want /models/weights", m)
	}
}

// The injected volume and mount are RECONSTRUCTED. ensureVolume and mountAll
// are both idempotent by skipping, so a host-authored spec that pre-declares
// either would otherwise choose where the plaintext lands.
func TestPreDeclaredVolumeAndMountAreOverwritten(t *testing.T) {
	pod := podWithApp()
	name := volumed.KubeVolumeName("weights")
	pod.Spec.Volumes = []corev1.Volume{{
		Name:         name,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}},
	}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
		Name:      name,
		MountPath: "/somewhere/the/author/picked",
		// Writable, unpropagated: what an author would choose to keep the
		// plaintext reachable and mutable.
	}}
	mutateWithVolumes(t, pod, []string{"weights=/tenant-a/volumes/weights"}, "")

	app := workloadContainer(t, pod, "app")
	m := mountNamed(app, name)
	if m == nil {
		t.Fatal("the mount was dropped")
	}
	if m.MountPath != "/run/c8s/volumes/weights" {
		t.Errorf("mount path = %q, want the webhook's own", m.MountPath)
	}
	if !m.ReadOnly {
		t.Error("a pre-declared writable mount survived")
	}
	if m.MountPropagation == nil || *m.MountPropagation != corev1.MountPropagationHostToContainer {
		t.Error("a pre-declared unpropagated mount survived")
	}

	// And the volume itself is the webhook's, bounded.
	var found *corev1.Volume
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			found = &pod.Spec.Volumes[i]
		}
	}
	if found == nil || found.EmptyDir == nil || found.EmptyDir.SizeLimit == nil {
		t.Fatalf("volume = %+v, want the webhook's bounded emptyDir", found)
	}
}

// Reserved by PREFIX, not by re-deriving names from the annotation: the
// annotation is host-written, so a guard reading it can be steered off the name
// it is meant to protect.
func TestReservedVolumePrefixMustBeMemoryBacked(t *testing.T) {
	for _, name := range []string{
		volumed.KubeVolumeName("weights"),
		volumed.KubeVolumePrefix + "not-even-requested",
	} {
		pod := podWithApp()
		pod.Spec.Volumes = []corev1.Volume{{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/tmp/exfil"},
			},
		}}
		if err := rejectReservedVolumeVolume(pod); err == nil {
			t.Errorf("%s: a hostPath under the reserved prefix was accepted", name)
		}
	}

	// The shape the webhook itself injects is fine, as is omitting it.
	pod := podWithApp()
	pod.Spec.Volumes = []corev1.Volume{openedVolume("weights")}
	if err := rejectReservedVolumeVolume(pod); err != nil {
		t.Errorf("the injected shape was rejected: %v", err)
	}
	if err := rejectReservedVolumeVolume(podWithApp()); err != nil {
		t.Errorf("an absent volume was rejected: %v", err)
	}
}

// `kubectl debug` with an allowlisted image would otherwise read the decrypted
// volume straight out of a live pod: the release check gates the fetch, and by
// then the mount already exists.
func TestEphemeralContainerMayNotMountAnOpenedVolume(t *testing.T) {
	pod := podWithApp()
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:         "debug",
			VolumeMounts: []corev1.VolumeMount{{Name: volumed.KubeVolumeName("weights")}},
		},
	}}
	if err := rejectEphemeralReservedMounts(pod); err == nil {
		t.Fatal("an ephemeral container mounted an opened volume")
	}
}

func TestEphemeralContainerMayNotTakeTheFetcherName(t *testing.T) {
	pod := podWithApp()
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: reservedVolumeContainerName},
	}}
	if err := rejectEphemeralReservedMounts(pod); err == nil {
		t.Fatal("an ephemeral container took the reserved fetcher name")
	}
}

func TestVolumesAnnotationValidation(t *testing.T) {
	for name, specs := range map[string][]string{
		"no pair":        {"weights"},
		"no name":        {"=/tenant-a/volumes/weights"},
		"not a label":    {"WEIGHTS=/tenant-a/volumes/weights"},
		"too long":       {"thirteenchars=/tenant-a/volumes/weights"},
		"relative path":  {"weights=tenant-a/volumes/weights"},
		"escaping path":  {"weights=/tenant-a/../../etc/shadow"},
		"repeated name":  {"weights=/tenant-a/volumes/a", "weights=/tenant-a/volumes/b"},
		"path with name": {"we/ights=/tenant-a/volumes/weights"},
	} {
		inj := &injection{WorkloadID: "api", Volumes: volumesSpec{Specs: specs}}
		if err := inj.validate(); err == nil {
			t.Errorf("%s: accepted %v", name, specs)
		}
	}

	ok := &injection{WorkloadID: "api", Volumes: volumesSpec{Specs: []string{
		"weights=/tenant-a/volumes/weights",
		"datasets=/tenant-a/volumes/datasets",
	}}}
	if err := ok.validate(); err != nil {
		t.Errorf("rejected a valid request: %v", err)
	}
}

func TestVolumeDirMustBeAbsolute(t *testing.T) {
	inj := &injection{WorkloadID: "api", Volumes: volumesSpec{
		Specs: []string{"weights=/tenant-a/volumes/weights"},
		Dir:   "relative/models",
	}}
	if err := inj.validate(); err == nil {
		t.Fatal("a relative volume dir was accepted")
	}
}

func TestVolumesAnnotationRequiresOptIn(t *testing.T) {
	pod := podWithApp()
	pod.Annotations = map[string]string{AnnotationVolumes: "weights=/tenant-a/volumes/weights"}
	if _, err := parseAnnotations(pod); err == nil {
		t.Fatal("volumes were requested without the workload annotation")
	}
}

func TestVolumesAnnotationParsing(t *testing.T) {
	pod := podWithApp()
	pod.Annotations = map[string]string{
		AnnotationWorkload:  "api",
		AnnotationVolumes:   "weights=/tenant-a/volumes/weights, datasets=/tenant-a/volumes/ds",
		AnnotationVolumeDir: "/models",
	}
	inj, err := parseAnnotations(pod)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(inj.Volumes.Specs) != 2 {
		t.Fatalf("specs = %v, want two", inj.Volumes.Specs)
	}
	if inj.Volumes.Dir != "/models" {
		t.Fatalf("dir = %q", inj.Volumes.Dir)
	}
}

// The kata shape: the fetcher hands the key to a node agent over the inventory
// socket directory, and the agent mounts into the pod's kubelet directory.
// Neither exists for a guest, so admission refuses rather than leaving the
// workload waiting on a mount that can never land.
func TestHandleRejectsVolumesWithoutTheNodeAgent(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsGuest = true

	resp := handleVolumesPod(t, cfg)
	if resp.Allowed {
		t.Fatal("admitted a volumes pod the node agent could never serve")
	}
	if msg := resp.Result.Message; !strings.Contains(msg, AnnotationVolumes) {
		t.Fatalf("denial %q does not name the offending annotation", msg)
	}
}

func TestHandleAdmitsVolumesWithTheNodeAgent(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/run/c8s/nri"

	if resp := handleVolumesPod(t, cfg); !resp.Allowed {
		t.Fatalf("Handle denied a serviceable volumes pod: %v", resp.Result)
	}
}

func handleVolumesPod(t *testing.T, cfg Config) admission.Response {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationVolumes:  "weights=/tenant-a/volumes/weights",
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

func initNames(pod *corev1.Pod) []string {
	out := make([]string, 0, len(pod.Spec.InitContainers))
	for _, c := range pod.Spec.InitContainers {
		out = append(out, c.Name)
	}
	return out
}

func workloadContainer(t *testing.T, pod *corev1.Pod, name string) *corev1.Container {
	t.Helper()
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	t.Fatalf("pod has no container %q", name)
	return nil
}

func mountNamed(c *corev1.Container, name string) *corev1.VolumeMount {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == name {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}

func mountNames(c *corev1.Container) []string {
	out := make([]string, 0, len(c.VolumeMounts))
	for _, m := range c.VolumeMounts {
		out = append(out, m.Name)
	}
	return out
}
