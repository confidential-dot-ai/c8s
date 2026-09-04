// Pod shape (c8s-pod): the kata confidential-VM install. Every workload pod
// is a kata CVM; the chart renders the kata-deploy stack, the platform's
// RuntimeClasses, the enforcement policy, the guest-image pullers and the
// confidential-GPU stack, and drops every host-side DaemonSet (their
// in-guest counterparts ship in kata-guest-base).
package helmchart

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/controller"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// TestChartKataEnabledRendersDeployStack: the pod chart renders the
// kata-deploy DaemonSet and the platform's RuntimeClasses — on the default
// (SNP) platform the two non-confidential classes plus the SNP pair; the TDX
// classes must NOT render (one CPU TEE per cluster).
func TestChartKataEnabledRendersDeployStack(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, rc := range []string{"kata-qemu", "kata-clh", "kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		if !renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Fatalf("pod chart missing RuntimeClass %q\n%s", rc, out)
		}
	}
	for _, rc := range []string{"kata-qemu-tdx", "kata-qemu-tdx-nvidia"} {
		if renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Fatalf("TDX RuntimeClass %q rendered on an SNP install — only the declared platform's classes ship\n%s", rc, out)
		}
	}

	ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
	if !ds.Spec.Template.Spec.HostPID {
		t.Errorf("kata-deploy DaemonSet must set hostPID: true (kata-deploy nsenters PID 1)")
	}
	c, ok := findContainer(ds.Spec.Template.Spec.Containers, "kube-kata")
	if !ok {
		t.Fatalf("kata-deploy DaemonSet missing kube-kata container; have %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Errorf("kube-kata container must run privileged (it installs a runtime onto the host); got %+v", c.SecurityContext)
	}

	// kata is enforcing: there is no kata-without-enforcement shape, so the
	// stack and the enforcement policy must arrive together.
	if !renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-kata-enforcement") {
		t.Errorf("the pod chart must render the enforcement policy — kata is enforcing")
	}
	if !slices.Contains(renderedOperatorArgs(t, out), "--kata-enforce=true") {
		t.Errorf("operator must get --kata-enforce on the pod shape — kata is enforcing")
	}
	// The webhook injects the platform's confidential classes; the operator
	// must be told which platform the chart rendered for.
	if !slices.Contains(renderedOperatorArgs(t, out), "--hardware-platform=sev-snp") {
		t.Errorf("operator must get --hardware-platform=sev-snp on a default kata install; args: %v", renderedOperatorArgs(t, out))
	}
	// The enforcement allowlist is platform-scoped too: a TDX class name must
	// not be admissible on an SNP install.
	expr := kataEnforcementExpressions(t, out)
	if strings.Contains(expr, "'kata-qemu-tdx'") || strings.Contains(expr, "'kata-qemu-tdx-nvidia'") {
		t.Errorf("kata-enforcement allowlist must not accept TDX classes on an SNP install\n%s", expr)
	}
}

// TestChartKataSnpRuntimeClassesCarryNodeSelector: the confidential classes
// must select SNP-labelled nodes (kata.snpNodeSelector). Without the selector
// a confidential pod scheduled onto a non-SNP TEE host (e.g. Intel TDX) does
// not fail cleanly — kata's confidential_guest auto-detects the host TEE and
// QEMU aborts in an unbounded crash-loop; with it the pod stays Pending with a
// clear scheduling message. kata-qemu / kata-clh work on any kata node and
// must stay unrestricted.
func TestChartKataSnpRuntimeClassesCarryNodeSelector(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, name := range []string{"kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		var rc rcScheduling
		if !findDoc(t, out, "RuntimeClass", name, &rc) {
			t.Fatalf("RuntimeClass %q not rendered\n%s", name, out)
		}
		if got := rc.Scheduling.NodeSelector["confidential.ai/sev-snp"]; got != "true" {
			t.Errorf("%s scheduling.nodeSelector[confidential.ai/sev-snp] = %q, want \"true\"", name, got)
		}
	}
	for _, name := range []string{"kata-qemu", "kata-clh"} {
		var rc rcScheduling
		if !findDoc(t, out, "RuntimeClass", name, &rc) {
			t.Fatalf("RuntimeClass %q not rendered\n%s", name, out)
		}
		if len(rc.Scheduling.NodeSelector) != 0 {
			t.Errorf("%s must carry no scheduling.nodeSelector (it runs on any kata node), got %v", name, rc.Scheduling.NodeSelector)
		}
	}
}

// kata.snpNodeSelector={} is the documented opt-out: the confidential classes
// render with no scheduling block (unrestricted scheduling, e.g. a uniformly
// SNP cluster that wants no capability label).
func TestChartKataSnpNodeSelectorClearable(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set", "kata.snpNodeSelector=null")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, name := range []string{"kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		var rc rcScheduling
		if !findDoc(t, out, "RuntimeClass", name, &rc) {
			t.Fatalf("RuntimeClass %q not rendered\n%s", name, out)
		}
		if len(rc.Scheduling.NodeSelector) != 0 {
			t.Errorf("%s scheduling.nodeSelector = %v, want none with kata.snpNodeSelector cleared", name, rc.Scheduling.NodeSelector)
		}
	}
}

// TestChartKataRendersGpuStack: a plain pod install (no GPU flag) ships the
// confidential-GPU stack — the GPU RuntimeClass (handler kata-qemu-nvidia-gpu-snp),
// the GPU shim in SHIMS_X86_64, the enforcement allowlist entry, the GPU image
// puller, and the privileged digest-pinned sandbox device plugin. GPU is part of
// every kata install; there is no separate toggle.
func TestChartKataRendersGpuStack(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// RuntimeClass name follows the c8s convention; handler is the kata shim.
	var rc struct {
		Handler string `yaml:"handler"`
	}
	if !findDoc(t, out, "RuntimeClass", "kata-qemu-snp-nvidia", &rc) {
		t.Fatalf("a kata install must render RuntimeClass kata-qemu-snp-nvidia\n%s", out)
	}
	if rc.Handler != "kata-qemu-nvidia-gpu-snp" {
		t.Errorf("kata-qemu-snp-nvidia handler = %q, want kata-qemu-nvidia-gpu-snp", rc.Handler)
	}

	// GPU shim registered with kata-deploy.
	ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
	kube, _ := findContainer(ds.Spec.Template.Spec.Containers, "kube-kata")
	if v := envValue(kube.Env, "SHIMS_X86_64"); !strings.Contains(v, "qemu-nvidia-gpu-snp") {
		t.Errorf("SHIMS_X86_64 = %q must register qemu-nvidia-gpu-snp", v)
	}

	// Enforcement allowlist accepts the class.
	if expr := kataEnforcementExpressions(t, out); !strings.Contains(expr, "'kata-qemu-snp-nvidia'") {
		t.Errorf("kata-enforcement allowlist must accept kata-qemu-snp-nvidia\n%s", expr)
	}

	// GPU image puller: pulls the -nvidia tag and patches the GPU config.
	puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
	pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
	if !ok {
		t.Fatalf("GPU puller missing reconcile container")
	}
	if got := envValue(pc.Env, "TAG"); got != "main-nvidia" {
		t.Errorf("GPU puller TAG = %q, want main-nvidia", got)
	}
	if got := envValue(pc.Env, "SHIM_NAME"); got != "qemu-nvidia-gpu-snp" {
		t.Errorf("GPU puller SHIM_NAME = %q, want qemu-nvidia-gpu-snp", got)
	}
	if got := envValue(pc.Env, "GPU_PCIE_ROOT_PORT"); got != "8" {
		t.Errorf("GPU puller GPU_PCIE_ROOT_PORT = %q, want 8", got)
	}

	// Sandbox device plugin: privileged, digest-pinned, advertises GPUs.
	plugin := renderedDaemonSet(t, out, "c8s-kata-deploy-sandbox-device-plugin")
	dp, ok := findContainer(plugin.Spec.Template.Spec.Containers, "nvidia-sandbox-device-plugin")
	if !ok {
		t.Fatalf("sandbox device plugin missing its container")
	}
	if dp.SecurityContext == nil || dp.SecurityContext.Privileged == nil || !*dp.SecurityContext.Privileged {
		t.Errorf("sandbox device plugin must run privileged (it mounts host /dev/vfio)")
	}
	if !strings.Contains(dp.Image, "@sha256:") {
		t.Errorf("sandbox device plugin image %q must be digest-pinned", dp.Image)
	}
}

// TestChartKataRendersGpuStackTdx: under platform=tdx
// the TDX classes render (and the SNP ones do NOT — one CPU TEE per cluster),
// the TDX shims register with kata-deploy, the enforcement allowlist accepts
// the TDX pair only, the GPU puller targets the qemu-nvidia-gpu-tdx shim
// (mirroring the non-GPU puller's qemu-tdx switch), and the operator is told
// the platform so webhook injection matches.
func TestChartKataRendersGpuStackTdx(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set", "platform=tdx")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var rc struct {
		Handler    string `yaml:"handler"`
		Scheduling struct {
			NodeSelector map[string]string `yaml:"nodeSelector"`
		} `yaml:"scheduling"`
	}
	if !findDoc(t, out, "RuntimeClass", "kata-qemu-tdx-nvidia", &rc) {
		t.Fatalf("a kata install must render RuntimeClass kata-qemu-tdx-nvidia\n%s", out)
	}
	if rc.Handler != "kata-qemu-nvidia-gpu-tdx" {
		t.Errorf("kata-qemu-tdx-nvidia handler = %q, want kata-qemu-nvidia-gpu-tdx", rc.Handler)
	}
	if got := rc.Scheduling.NodeSelector["confidential.ai/tdx"]; got != "true" {
		t.Errorf("kata-qemu-tdx-nvidia nodeSelector[confidential.ai/tdx] = %q, want \"true\" (same guard as kata-qemu-tdx)", got)
	}

	ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
	kube, _ := findContainer(ds.Spec.Template.Spec.Containers, "kube-kata")
	if v := envValue(kube.Env, "SHIMS_X86_64"); !strings.Contains(v, "qemu-nvidia-gpu-tdx") {
		t.Errorf("SHIMS_X86_64 = %q must register qemu-nvidia-gpu-tdx", v)
	}
	if v := envValue(kube.Env, "SNAPSHOTTER_HANDLER_MAPPING_X86_64"); !strings.Contains(v, "qemu-nvidia-gpu-tdx:nydus") {
		t.Errorf("SNAPSHOTTER_HANDLER_MAPPING_X86_64 = %q must route qemu-nvidia-gpu-tdx through nydus", v)
	}

	expr := kataEnforcementExpressions(t, out)
	if !strings.Contains(expr, "'kata-qemu-tdx-nvidia'") {
		t.Errorf("kata-enforcement allowlist must accept kata-qemu-tdx-nvidia\n%s", expr)
	}

	puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
	pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
	if !ok {
		t.Fatalf("GPU puller missing reconcile container")
	}
	if got := envValue(pc.Env, "SHIM_NAME"); got != "qemu-nvidia-gpu-tdx" {
		t.Errorf("GPU puller SHIM_NAME = %q, want qemu-nvidia-gpu-tdx on a TDX cluster", got)
	}

	// One CPU TEE per cluster: the SNP classes must not render on TDX, the
	// SNP shims must not register, and the allowlist must not accept them.
	for _, rc := range []string{"kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		if renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Errorf("SNP RuntimeClass %q rendered on a TDX install — only the declared platform's classes ship", rc)
		}
	}
	if v := envValue(kube.Env, "SHIMS_X86_64"); strings.Contains(v, "-snp") {
		t.Errorf("SHIMS_X86_64 = %q must not register SNP shims on a TDX install", v)
	}
	if strings.Contains(expr, "'kata-qemu-snp'") || strings.Contains(expr, "'kata-qemu-snp-nvidia'") {
		t.Errorf("kata-enforcement allowlist must not accept SNP classes on a TDX install\n%s", expr)
	}
	if !strings.Contains(expr, "'kata-qemu-tdx'") {
		t.Errorf("kata-enforcement allowlist must accept kata-qemu-tdx on a TDX install\n%s", expr)
	}

	// Webhook injection follows the platform.
	if !slices.Contains(renderedOperatorArgs(t, out), "--hardware-platform=tdx") {
		t.Errorf("operator must get --hardware-platform=tdx on a TDX kata install; args: %v", renderedOperatorArgs(t, out))
	}
}

// TestChartKataSandboxDevicePluginOptOut: the privileged sandbox device plugin
// (the only nvcr.io-pulled, host-/dev/vfio-mounting GPU component) can be opted
// out via kata.gpu.sandboxDevicePlugin.enabled while the rest of the GPU stack
// (runtime class, shim, puller) still ships.
func TestChartKataSandboxDevicePluginOptOut(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set", "kata.gpu.sandboxDevicePlugin.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-kata-deploy-sandbox-device-plugin") {
		t.Errorf("sandbox device plugin rendered with sandboxDevicePlugin.enabled=false")
	}
	if !renderedManifestHasNamedKind(t, out, "RuntimeClass", "kata-qemu-snp-nvidia") {
		t.Errorf("the rest of the GPU stack must still render with the device plugin opted out")
	}
}

// TestChartKataDistroSelectsContainerdConfigDir: the distro value must
// pick the right host containerd config dir for kata-deploy to bind.
func TestChartKataDistroSelectsContainerdConfigDir(t *testing.T) {
	for _, tc := range []struct {
		distro string
		want   string
	}{
		{"k8s", "/etc/containerd"},
		{"rke2", "/var/lib/rancher/rke2/agent/etc/containerd"},
	} {
		t.Run(tc.distro, func(t *testing.T) {
			out, err := helmTemplate(t, chartPod, "--set-string", "distro="+tc.distro)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
			if got := hostPathVolume(t, ds, "containerd-conf"); got != tc.want {
				t.Fatalf("distro %q: containerd-conf hostPath = %q, want %q", tc.distro, got, tc.want)
			}
		})
	}
}

func TestChartKataRejectsUnknownDistro(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set-string", "distro=openshift")
	if err == nil {
		t.Fatalf("helm template succeeded for an unknown distro, want failure\n%s", out)
	}
}

// TestChartKataContainerdPrepInitContainer: on rke2 the kata-deploy DaemonSet
// must carry a containerd-prep initContainer that wires up the drop-in import
// before kube-kata runs; on k8s kata-deploy edits containerd directly, so the
// prep must be absent.
func TestChartKataContainerdPrepInitContainer(t *testing.T) {
	t.Run("rke2", func(t *testing.T) {
		out, err := helmTemplate(t, chartPod, "--set-string", "distro=rke2")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
		prep, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep")
		if !ok {
			t.Fatalf("rke2: kata-deploy DaemonSet missing containerd-prep initContainer; have %v",
				containerNames(ds.Spec.Template.Spec.InitContainers))
		}
		if prep.SecurityContext == nil || prep.SecurityContext.Privileged == nil || !*prep.SecurityContext.Privileged {
			t.Errorf("containerd-prep must run privileged (it edits the host containerd config)")
		}
		env := initContainerEnv(t, ds, "containerd-prep")
		if got := env["HOST_CONTAINERD_DIR"]; got != "/var/lib/rancher/rke2/agent/etc/containerd" {
			t.Errorf("HOST_CONTAINERD_DIR = %q, want the rke2 containerd dir", got)
		}
		if got := env["BASE_DIRECTIVE"]; got != `{{ template "base" . }}` {
			t.Errorf("BASE_DIRECTIVE = %q, want the literal RKE2 base include", got)
		}
	})

	t.Run("k8s", func(t *testing.T) {
		out, err := helmTemplate(t, chartPod, "--set-string", "distro=k8s")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
		if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); ok {
			t.Fatalf("k8s: kata-deploy must not carry a containerd-prep initContainer")
		}
	})
}

// Contract with the `c8s uninstall` running-pod guard (cmd/c8s/uninstall.go,
// filterKataPods): it skips the release's own kata pods by release namespace +
// app.kubernetes.io/instance, so every kata-pinned pod template must carry that
// label or a clean uninstall is refused again.
func TestChartKataPinnedPodsCarryInstanceLabel(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var pinned []string
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		rc := obj.Spec.Template.Spec.RuntimeClassName
		if rc == nil || !strings.HasPrefix(*rc, "kata-") {
			return false
		}
		pinned = append(pinned, obj.Metadata.Name)
		if got := obj.Spec.Template.Labels["app.kubernetes.io/instance"]; got != "c8s" {
			t.Errorf("%s pod template: app.kubernetes.io/instance = %q, want the release name", obj.Metadata.Name, got)
		}
		return false
	})
	slices.Sort(pinned)
	if want := []string{"c8s-cds", "c8s-tls-lb"}; !reflect.DeepEqual(pinned, want) {
		t.Errorf("kata-pinned workloads = %v, want %v", pinned, want)
	}
}

// Contract with KataGuestReadyReconciler (internal/controller): it lists the
// puller pods by this label pair and mirrors their readiness into
// webhook.GuestReadyNodeLabel. If the rendered label drifts, the list matches
// nothing, the label is never set, and every confidential pod stays Pending.
func TestChartKataImagePullerCarriesControllerSelector(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller")
	if got := ds.Spec.Template.Labels[controller.ComponentLabel]; got != controller.KataImagePullerComponent {
		t.Fatalf("puller pod template: %s = %q, want %q", controller.ComponentLabel, got, controller.KataImagePullerComponent)
	}
}

// The check stats the pulled artifacts across the /host bind mount, so
// kubelet's 1s default probe timeout would drop the guest-ready label off a
// healthy node under load.
func TestChartKataImagePullerProbeTimeout(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, ds := range []string{"c8s-kata-deploy-image-puller", "c8s-kata-deploy-image-puller-nvidia"} {
		probe := renderedDaemonSetContainer(t, out, ds, "reconcile").ReadinessProbe
		if probe == nil || probe.Exec == nil {
			t.Fatalf("%s: want an exec readiness probe, got %+v", ds, probe)
		}
		if probe.TimeoutSeconds != 5 {
			t.Errorf("%s: readiness timeoutSeconds = %d, want 5", ds, probe.TimeoutSeconds)
		}
	}
}

func TestChartKataTLSLBAllowlistProxyUsesGuestAttestationAPI(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	proxy := renderedDeploymentContainer(t, out, "c8s-tls-lb", "allowlist-proxy")
	assertContainerHasArg(t, "allowlist-proxy", proxy.Args, "--attestation-api-url=http://127.0.0.1:8400")
	if hasHostIPEnv(proxy) {
		t.Fatalf("kata allowlist-proxy must use guest loopback, not HOST_IP: env=%v", proxy.Env)
	}
}

// TestChartKataRendersPolicyAndOperatorFlag: the pod chart renders the
// ValidatingAdmissionPolicy + binding and flips the operator's --kata-enforce
// flag — the two halves of enforcement must move together, and kata is
// enforcing by definition.
func TestChartKataRendersPolicyAndOperatorFlag(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-kata-enforcement") {
		t.Fatalf("kata enforcement missing ValidatingAdmissionPolicy\n%s", out)
	}
	if !renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicyBinding", "c8s-kata-enforcement") {
		t.Fatalf("kata enforcement missing ValidatingAdmissionPolicyBinding\n%s", out)
	}
	if !slices.Contains(renderedOperatorArgs(t, out), "--kata-enforce=true") {
		t.Fatalf("operator missing --kata-enforce=true with enforcement on\n%s", out)
	}
}

// pcie_root_port=0 disables VFIO cold-plug: a GPU pod would boot as a
// confidential VM with no device and the only symptom is a missing
// /dev/nvidia* in-guest. The chart must refuse the render instead of
// shipping that silently (the puller script double-checks at run time).
func TestChartKataRejectsZeroPcieRootPort(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set", "kata.gpu.guestImage.pcieRootPort=0")
	if err == nil {
		t.Fatalf("helm template succeeded with kata.gpu.guestImage.pcieRootPort=0, want failure\n%s", out)
	}
	if msg := helmFailMessage(t, out); !strings.Contains(msg, "kind=gpu_pcie_root_port") {
		t.Errorf("fail message %q missing the gpu_pcie_root_port marker", msg)
	}
}

// The pod shape must drop the host-side DaemonSets entirely — their
// in-guest counterparts ship in kata-guest-base.
func TestChartKataShapeDropsHostSideComponents(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-attestation-api") {
		t.Errorf("kata shape still renders the host attestation-api DaemonSet")
	}
	for _, component := range []string{"ratls-mesh", "nri-image-policy"} {
		if renderedManifestHasLabel(t, out, "app.kubernetes.io/name", component) {
			t.Errorf("kata shape still renders %s manifests", component)
		}
	}
}

// tls-lb lives in the release namespace, which the kata-enforcement webhook
// deliberately excludes — so the chart itself must pin the confidential
// RuntimeClass on it under kata, exactly like cds.yaml. kata-qemu-snp
// specifically: its get-cert containers dial the in-guest attestation-api on
// loopback (c8s.attestationApiURL), which only exists inside an SNP guest.
func TestChartKataPinsRuntimeClassOnTLSLB(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-tls-lb")
	rc := dep.Spec.Template.Spec.RuntimeClassName
	if rc == nil || *rc != "kata-qemu-snp" {
		t.Errorf("c8s-tls-lb runtimeClassName = %v, want kata-qemu-snp", rc)
	}
}

// Pods pinning a kata RuntimeClass bypass the injecting webhook.
func TestChartKataPinnedPodsCarryGuestReadyAffinity(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seen := map[string]bool{}
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		spec := obj.Spec.Template.Spec
		if spec.RuntimeClassName == nil || !strings.HasPrefix(*spec.RuntimeClassName, "kata-") {
			return false
		}
		if spec.Affinity == nil || spec.Affinity.NodeAffinity == nil ||
			spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			t.Errorf("%s %s pins %s but has no required node affinity", obj.Kind, obj.Metadata.Name, *spec.RuntimeClassName)
			return false
		}
		for _, term := range spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
			for _, e := range term.MatchExpressions {
				if e.Key == webhook.GuestReadyNodeLabel {
					seen[obj.Metadata.Name] = true
				}
			}
		}
		if !seen[obj.Metadata.Name] {
			t.Errorf("%s %s pins %s without the guest-ready gate", obj.Kind, obj.Metadata.Name, *spec.RuntimeClassName)
		}
		return false
	})
	for _, name := range []string{"c8s-cds", "c8s-tls-lb"} {
		if !seen[name] {
			t.Errorf("%s missing the guest-ready node affinity", name)
		}
	}
}

// The one install shape granting the operator node RBAC. Asserted exactly
// here: TestChartOperatorRBACIsScoped's ban never renders this branch.
func TestChartOperatorNodeRBACOnlyUnderKataGuestReadyGate(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	got := operatorVerbsFor(role, "", "nodes")
	want := []string{"get", "list", "watch", "patch"}
	if !slices.Equal(got, want) {
		t.Fatalf("operator nodes verbs under kata = %v, want %v", got, want)
	}

	// No puller, no controller: the grant and the gate must both go with it.
	out, err = helmTemplate(t, chartPod, "--set", "kata.guestImage.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	if got := operatorVerbsFor(role, "", "nodes"); got != nil {
		t.Fatalf("operator keeps nodes verbs %v with the puller disabled", got)
	}
	if strings.Contains(out, "kata-guest-ready-gate=true") {
		t.Fatal("operator still told to enforce the guest-ready gate with no puller to set the label")
	}
}

// The puller's in-pod `oras pull` ignores kubelet imagePullSecrets, so the
// install-time pull secret must also feed its dockercfg mount — otherwise
// `c8s install --image-pull-secret` would cover every kubelet pull but leave
// the kata-guest-base fetch anonymous (401 against a private registry).
func TestChartImagePullSecretFeedsKataImagePuller(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set-string", "imagePullSecret=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerDockercfgSecret(t, out); got != "ghcr-secret" {
		t.Errorf("puller dockercfg secret = %q, want ghcr-secret", got)
	}
}

// An explicit pullerAuthSecret wins over the imagePullSecret default — the
// guest-base artifact may need a different credential than the c8s images.
func TestChartKataPullerAuthSecretOverridesImagePullSecret(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set-string", "imagePullSecret=ghcr-secret",
		"--set-string", "kata.guestImage.pullerAuthSecret=other-creds")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerDockercfgSecret(t, out); got != "other-creds" {
		t.Errorf("puller dockercfg secret = %q, want other-creds", got)
	}
}

// kata.guestImage.debug must repoint the puller at the `<tag>-debug` artifact
// — the variant whose guest policy allows host log/exec streams (published in
// lockstep by the kata-guest-base workflow; `c8s install --cvm-mode=pod --debug` sets
// the value). Default off: a plain kata install pulls the locked image.
func TestChartKataGuestImageDebugSelectsDebugTag(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerEnv(t, out, "TAG"); got != "main" {
		t.Errorf("default puller TAG = %q, want main (locked image)", got)
	}

	out, err = helmTemplate(t, chartPod, "--set", "kata.guestImage.debug=true")
	if err != nil {
		t.Fatalf("helm template (debug): %v\n%s", err, out)
	}
	if got := pullerEnv(t, out, "TAG"); got != "main-debug" {
		t.Errorf("debug puller TAG = %q, want main-debug", got)
	}
}

// kata.guestImage.debug must vary the GPU guest tag in lockstep with the
// non-GPU one: CI publishes `<tag>-nvidia` and `<tag>-nvidia-debug` together
// (kata-guest-base.yml build job, build.sh Step 6) — see
// c8s.kataGuestImageNvidiaTag.
func TestChartKataGuestImageDebugDerivesNvidiaDebugTag(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set", "kata.guestImage.debug=true")
	if err != nil {
		t.Fatalf("helm template (debug): %v\n%s", err, out)
	}
	puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
	pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
	if !ok {
		t.Fatalf("GPU puller missing reconcile container")
	}
	if got := envValue(pc.Env, "TAG"); got != "main-nvidia-debug" {
		t.Errorf("GPU puller TAG under debug = %q, want main-nvidia-debug (published in lockstep with main-nvidia)", got)
	}
	if got := envValue(pc.Env, "KATA_DEBUG"); got != "true" {
		t.Errorf("GPU puller KATA_DEBUG under debug = %q, want true", got)
	}
}

// With neither value set the pull stays anonymous: no dockercfg volume at all
// (the default shape — the published artifacts are public).
func TestChartKataPullerAnonymousWithoutSecrets(t *testing.T) {
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerDockercfgSecret(t, out); got != "" {
		t.Errorf("puller dockercfg secret = %q, want none (anonymous pull)", got)
	}
}

// Under kata the host NRI plugin is off, but admission is the in-guest
// policy-monitor fed from CDS's served allowlist, so the seed must still render.
// Otherwise adopted --workload-ref digests (in bootstrapAllowlist.digests) never
// reach CDS and the in-guest monitor denies those images.
func TestChartRendersCDSSeedUnderKata(t *testing.T) {
	const (
		wlDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
		wlRepo   = "example.test/vllm-router"
	)
	out, err := helmTemplate(t, chartPod, "--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+wlDigest+"="+wlRepo+"@"+wlDigest)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if got, want := seed.Digests[wlDigest], wlRepo+"@"+wlDigest; got != want {
		t.Errorf("adopted workload digest not in kata seed = %q, want %q\nseed: %v", got, want, seed.Digests)
	}
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	if !slices.Contains(cds.Args, "--allowlist-seed=/etc/cds/allowlist-seed.json") {
		t.Errorf("cds missing --allowlist-seed flag under kata\nargs: %v", cds.Args)
	}
}

// The host qemu wrapper needs one source of truth: the puller ConfigMap ships a
// copy, and kata-guest-base scripts/ holds the canonical file because it lives
// alongside the guest tooling it is coupled to. A silent drift would be a
// launch-behaviour drift the launch measurement can't catch (the wrapper runs
// on the host outside every attested boundary).
func TestKataQemuWrapperCopiesMatch(t *testing.T) {
	// The chart copy ships in the package tree; the canonical source lives in
	// the kata-guest-base tree, reached from the package source dir.
	var (
		chart  = "scripts/kata-qemu-scratch-wrapper.sh"
		source = filepath.Join(chartSrcDir, "..", "..", "kata-guest-base", "scripts", "kata-qemu-scratch-wrapper.sh")
	)
	chartBytes, err := os.ReadFile(chart)
	if err != nil {
		t.Fatalf("read %s: %v", chart, err)
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	if !slices.Equal(chartBytes, sourceBytes) {
		t.Fatalf("wrapper drift: %s and %s must be byte-identical\n"+
			"the puller ConfigMap uses the chart copy; the guest-base tree is the source of truth\n"+
			"fix: cp %s %s", chart, source, source, chart)
	}
}

// kata is enforcing: every workload is a kata CVM, and the webhook injects
// the c8s sidecars into every confidential pod off `image`, where the guest
// admits only digest-pinned references. A tag renders sidecars the guest
// refuses at CreateContainer, so the pod chart refuses the render instead.
func TestChartKataRequiresImageDigest(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set-string", "image.digest=")
	if err == nil {
		t.Fatalf("helm template succeeded with a tag-only image on the pod shape, want failure\n%s", out)
	}
	msg := helmFailMessage(t, out)
	if !strings.Contains(msg, "kind=kata_image_digest") {
		t.Errorf("fail message %q missing the kata_image_digest marker", msg)
	}
}

// The pod shape points every pod-netns consumer (cds, tls-lb's cert sidecar,
// cds-attest, allowlist-proxy) at the attestation-service baked into the kata
// guest image on the CVM's loopback. No consumer mounts the node socket
// directory, and no HOST_IP env renders anywhere (that is the node-image
// wiring). The operator forwards its --attestation-api-url verbatim into the
// tenant get-cert sidecars it injects.
func TestPodAttestationURLUsesGuestLoopback(t *testing.T) {
	const loopbackURL = "--attestation-api-url=http://127.0.0.1:8400"
	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	for _, c := range []corev1.Container{
		renderedDeploymentContainer(t, out, "c8s-cds", "cds"),
		tlsLBGetCertContainer(t, out, "c8s-cert"),
		renderedDeploymentContainer(t, out, "c8s-tls-lb", "cds-attest"),
		renderedDeploymentContainer(t, out, "c8s-tls-lb", "allowlist-proxy"),
	} {
		assertContainerArgs(t, c, loopbackURL)
		for _, m := range c.VolumeMounts {
			if m.Name == "attestation-api-socket" {
				t.Errorf("pod shape: container %s must not mount the node attestation socket", c.Name)
			}
		}
	}

	for _, w := range renderedPodSpecs(t, out) {
		for _, c := range append(append([]corev1.Container{}, w.spec.InitContainers...), w.spec.Containers...) {
			for _, e := range c.Env {
				if e.Name == "HOST_IP" {
					t.Errorf("pod shape must not render any HOST_IP env; %s %s container %s carries it", w.kind, w.name, c.Name)
				}
			}
		}
	}
}

// Under kata the RA-TLS mesh moves into the guest, so the pod's serving port
// is fronted by the in-guest inbound proxy that expects mutual attested TLS.
// The kubelet prober presents no attested client cert, so an httpGet probe is
// rejected at the handshake ("tls: certificate required") and the container
// CrashLoopBackOffs on failed probes. The chart must fall back to a tcpSocket
// probe under kata (same pattern and rationale as cds.yaml).
func TestPodTLSLBProbesAvoidMTLSHandshake(t *testing.T) {
	type namedProbe struct {
		name  string
		probe *corev1.Probe
	}

	out, err := helmTemplate(t, chartPod)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-tls-lb", "nginx")
	for _, p := range []namedProbe{
		{"readiness", nginx.ReadinessProbe},
		{"liveness", nginx.LivenessProbe},
	} {
		if p.probe == nil || p.probe.TCPSocket == nil {
			t.Fatalf("pod shape: tls-lb %s probe should be tcpSocket (an httpGet hits the in-guest mTLS handshake); got %+v", p.name, p.probe)
		}
		if got := p.probe.TCPSocket.Port.String(); got != "https" {
			t.Errorf("pod shape: tls-lb %s probe tcpSocket port = %q, want https", p.name, got)
		}
		if p.probe.HTTPGet != nil {
			t.Errorf("pod shape: tls-lb %s probe must not be httpGet", p.name)
		}
	}
}

// The /readyz matched-workload gate under kata: the guest serves the
// inventory on loopback, so get-cert takes the guest flag and the pod carries
// no node-socket mount — and the probe rides the nginx port, the one port the
// guest exempts from the inbound mesh redirect.
func TestPodTLSLBReadinessGate(t *testing.T) {
	out, err := helmTemplate(t, chartPod,
		"--set-string", "tlsLb.attest.expectedWorkload=infer",
		"--set", "tlsLb.hostPort.enabled=false",
	)
	if err != nil {
		t.Fatalf("helm template with expectedWorkload: %v\n%s", err, out)
	}
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-tls-lb"), "c8s-cert")
	if !ok {
		t.Fatal("c8s-cert init container missing")
	}
	assertContainerArgs(t, cert, "--workload-claims", "--workload-claims-guest")
	for _, m := range cert.VolumeMounts {
		if m.Name == "workload-claims" {
			t.Fatal("kata get-cert must not mount the node socket")
		}
	}
	assertContainerArgs(t, renderedDeploymentContainer(t, out, "c8s-tls-lb", "cds-attest"), "--host=127.0.0.1")
	// The probe shape is the whole reason this gate is reachable under kata:
	// the guest exempts only the nginx port from the inbound mesh redirect.
	assertTLSLBReadyzProbe(t, out)
	dep := renderedDeployment(t, out, "c8s-tls-lb")
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "workload-claims" {
			t.Fatal("kata pod must not carry the node inventory hostPath volume")
		}
	}
	if sc := dep.Spec.Template.Spec.SecurityContext; sc != nil && len(sc.SupplementalGroups) != 0 {
		t.Fatalf("kata pod needs no inventory socket group, got %+v", sc.SupplementalGroups)
	}
}

// The probe and every external client reach nginx only on the one port the
// guest exempts from the inbound mesh redirect; any other port is refused at
// render time.
func TestPodTLSLBReadinessGateRejectsNonExemptNginxPort(t *testing.T) {
	out, err := helmTemplate(t, chartPod, "--set", "tlsLb.nginx.httpsPort=9443")
	if err == nil {
		t.Fatalf("render succeeded, want a fail\n%s", out)
	}
	assertHelmFailMessage(t, out, "the pod shape requires tlsLb.nginx.httpsPort 8443: the guest exempts exactly tcp:8443 from the inbound mesh redirect, so nginx on any other port is unreachable from outside the mesh, got: 9443")
}
