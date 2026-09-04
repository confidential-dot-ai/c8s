// Node-cloud shape (c8s-node-cloud): managed confidential VM nodes (GKE,
// AKS). GKE CVMs expose the native TEE device (platform snp|tdx); Azure CVMs
// attest through the vTPM (platform az-snp|az-tdx, tpm mounts + the AKS
// webhook opt-out). The chart defaults to distro=k8s and exempts kube-system
// from image admission.
package helmchart

import (
	"slices"
	"strings"
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
)

// platform derives the TEE device the attestation-api DaemonSet mounts: the
// native guest device on bare/cloud SNP, the TSM configfs on TDX (bare-metal
// TDX has no /dev/tdx-guest — that is a guest-side device), and the vTPM pair
// on the Azure platforms.
func TestCloudAttestationApiDeviceDerivesFromPlatform(t *testing.T) {
	for _, tc := range []struct {
		platform string
		// hostPath volumes the attestation-api pod must carry, with the
		// device path each mounts.
		wantVolumes map[string]string
	}{
		{"snp", map[string]string{"sev-guest": "/dev/sev-guest"}},
		{"tdx", map[string]string{"tdx-tsm-configfs": "/sys/kernel/config"}},
		{"az-snp", map[string]string{"tpm": "/dev/tpm0", "tpmrm": "/dev/tpmrm0"}},
		{"az-tdx", map[string]string{"tpm": "/dev/tpm0", "tpmrm": "/dev/tpmrm0"}},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			out, err := helmTemplate(t, chartNodeCloud, "--set", "platform="+tc.platform)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			ds := renderedDaemonSet(t, out, "c8s-attestation-api")
			spec := ds.Spec.Template.Spec
			for volName, path := range tc.wantVolumes {
				v, ok := podVolume(spec, volName)
				if !ok || v.HostPath == nil {
					t.Fatalf("platform=%s: attestation-api missing hostPath volume %q; volumes=%v", tc.platform, volName, spec.Volumes)
				}
				if v.HostPath.Path != path {
					t.Errorf("platform=%s: volume %q hostPath = %q, want %q", tc.platform, volName, v.HostPath.Path, path)
				}
				api := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
				if m, ok := containerVolumeMount(api, volName); !ok || m.MountPath != path {
					t.Errorf("platform=%s: attestation-api mount %q = (%+v, %v), want mountPath %q", tc.platform, volName, m, ok, path)
				}
			}
		})
	}
}

// Every RA-TLS surface derives from the one platform value: the mesh peer
// platform, CDS's serving platform, and the attest sidecar's
// platform/generation (generation applies only to bare SNP).
func TestCloudTdxPlatformDerivations(t *testing.T) {
	out, err := helmTemplate(t, chartNodeCloud, "--set", "platform=tdx")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if !argvContainsFlagValue(meshArgs, "--platform", "tdx") {
		t.Errorf("ratls-mesh --platform must derive tdx; args=%q", meshArgs)
	}
	cdsArgs := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", cdsArgs, "--ratls-platform=tdx")
	attestArgs := renderedDeploymentContainer(t, out, "c8s-tls-lb", "cds-attest").Args
	assertContainerHasArg(t, "cds-attest", attestArgs, "--platform=tdx")
	assertContainerHasArg(t, "cds-attest", attestArgs, "--generation=")
}

// The SNP defaults: mesh peers sev-snp, attest --platform=snp with the AMD
// generation kept.
func TestCloudSnpPlatformDerivations(t *testing.T) {
	out, err := helmTemplate(t, chartNodeCloud)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if !argvContainsFlagValue(meshArgs, "--platform", "sev-snp") {
		t.Errorf("ratls-mesh --platform must default to sev-snp; args=%q", meshArgs)
	}
	cdsArgs := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", cdsArgs, "--ratls-platform=snp")
	attestArgs := renderedDeploymentContainer(t, out, "c8s-tls-lb", "cds-attest").Args
	assertContainerHasArg(t, "cds-attest", attestArgs, "--platform=snp")
	assertContainerHasArg(t, "cds-attest", attestArgs, "--generation=genoa")
}

// TestChartWebhookOptsOutOfAKSAdmissionsEnforcer proves the AKS workaround:
// on the Azure platforms (what `c8s install --evidence vtpm` sets) the
// pod-injector MutatingWebhookConfiguration carries
// admissions.enforcer/disabled=true, so AKS's admissionsenforcer controller
// stops rewriting the webhook namespaceSelector and conflicting with helm
// re-applies. The native platforms must NOT carry it — the annotation is
// pure AKS plumbing and shouldn't appear on other platforms. A user-set
// webhook.annotations value flows through alongside it.
func TestChartWebhookOptsOutOfAKSAdmissionsEnforcer(t *testing.T) {
	const annotation = "admissions.enforcer/disabled"

	// Default (snp): no AKS opt-out annotation.
	out, err := helmTemplate(t, chartNodeCloud)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var def admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &def) {
		t.Fatalf("default chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if _, ok := def.Annotations[annotation]; ok {
		t.Errorf("default (snp) webhook must not carry %s; got %v", annotation, def.Annotations)
	}

	// az-snp: opt-out annotation present and "true".
	out, err = helmTemplate(t, chartNodeCloud, "--set", "platform=az-snp")
	if err != nil {
		t.Fatalf("helm template platform=az-snp: %v\n%s", err, out)
	}
	var aks admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &aks) {
		t.Fatalf("az-snp chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if got := aks.Annotations[annotation]; got != "true" {
		t.Errorf("az-snp webhook %s = %q, want \"true\"; annotations=%v", annotation, got, aks.Annotations)
	}

	// A user-supplied annotation coexists with the automatic AKS opt-out.
	out, err = helmTemplate(t, chartNodeCloud,
		"--set", "platform=az-snp",
		"--set-string", "webhook.annotations.team=platform",
	)
	if err != nil {
		t.Fatalf("helm template with extra webhook annotation: %v\n%s", err, out)
	}
	var both admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &both) {
		t.Fatalf("override chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if got := both.Annotations["team"]; got != "platform" {
		t.Errorf("user webhook.annotations.team = %q, want \"platform\"; annotations=%v", got, both.Annotations)
	}
	if got := both.Annotations[annotation]; got != "true" {
		t.Errorf("AKS opt-out must still apply alongside user annotations: %s = %q, want \"true\"", annotation, got)
	}
}

func TestChartRendersManagedClusterKnobs(t *testing.T) {
	out, err := helmTemplate(t, chartNodeCloud,
		"--set", "serviceAccount.imagePullSecrets[0].name=ghcr-secret",
		"--set", "platform=az-snp",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var sa corev1.ServiceAccount
	if !findDoc(t, out, "ServiceAccount", "c8s-operator", &sa) {
		t.Fatalf("render missing ServiceAccount c8s-operator\n%s", out)
	}
	if !hasPullSecret(sa.ImagePullSecrets, "ghcr-secret") {
		t.Fatalf("operator ServiceAccount missing chart-wide pull secret ghcr-secret: %v", sa.ImagePullSecrets)
	}
	// az-snp → privileged attestation-api with a read-only root filesystem.
	sc := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api").SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Fatalf("attestation-api must be privileged under az-snp; got %+v", sc)
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("attestation-api must set readOnlyRootFilesystem: true; got %+v", sc)
	}
}

// TestChartAttestationApiPrivileged proves every platform renders privileged:
// true. A hostPath device mount does not add a device-cgroup rule, so open()
// on the TEE device (/dev/sev-guest, /dev/tpm0) is EPERM from an unprivileged
// container regardless of SYS_RAWIO (cgroup v2 eBPF device controller); the
// vTPM additionally gates below the capability layer.
func TestChartAttestationApiPrivileged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chart string
		args  []string
	}{
		{name: "node-metal snp (chart default)", chart: chartNodeMetal},
		{name: "node-cloud snp", chart: chartNodeCloud},
		{name: "node-cloud az-snp", chart: chartNodeCloud, args: []string{"--set", "platform=az-snp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.chart, tc.args...)
			if err != nil {
				t.Fatalf("helm template (%s): %v\n%s", tc.name, err, out)
			}
			c := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
			sc := c.SecurityContext
			if sc == nil || sc.Privileged == nil || !*sc.Privileged {
				t.Errorf("%s must be privileged for device access; got %+v", tc.name, sc)
			}
		})
	}
}

// node-cloud defaults nriImagePolicy.policy.exemptNamespaces to [kube-system]:
// the provider's platform pods are not on the c8s allowlist, so the plugin
// admits them by the digests captured running in that namespace.
func TestCloudBootConfigExemptsKubeSystemByDefault(t *testing.T) {
	out, err := helmTemplate(t, chartNodeCloud)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if got := cfg.Policy.ExemptNamespaces; !slices.Equal(got, []string{"kube-system"}) {
		t.Errorf("exempt_namespaces = %v, want [kube-system]", got)
	}
}

// node-cloud defaults to distro=k8s: the tls-lb resolver is kube-dns and the
// NRI installer patches /etc/containerd in place (no containerd-prep init
// container, a plain containerd restart).
func TestCloudDistroDefaultsToK8s(t *testing.T) {
	out, err := helmTemplate(t, chartNodeCloud)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	renderedTLSLBNginxConfig(t, out).http.assertDirective(t, "resolver", "kube-dns.kube-system.svc.cluster.local")

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); ok {
		t.Errorf("distro=k8s: nri installer must not carry a containerd-prep initContainer")
	}
	if got := hostPathVolume(t, ds, "host-containerd-config"); got != "/etc/containerd" {
		t.Errorf("host-containerd-config hostPath = %q, want /etc/containerd", got)
	}
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	for _, want := range []string{
		"CONTAINERD_DIR=/host/etc/containerd",
		`CONTAINERD_CONFIG_MODE="patch"`,
		`RESTART_COMMAND="systemctl restart containerd"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script missing %q", want)
		}
	}
}
