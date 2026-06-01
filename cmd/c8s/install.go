//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lunal-dev/c8s/internal/helmchart"
	"github.com/lunal-dev/c8s/internal/version"
)

var (
	installNamespace string
	installRelease   string
	installValues    []string
	installWait      bool
	installCRDs      bool

	installCertFSGroup          int64
	installCertKeyMode          string
	installGetCertRenewInterval time.Duration
	installGetCertRunAsUser     int64
	installGetCertRunAsGroup    int64
	installGetCertRunAsNonRoot  bool

	installKata        bool
	installKataEnforce bool
	installDistro      string

	installResolveDigests bool
)

// c8sComponent maps a chart image to the helm value keys --resolve-digests
// pins. valuePrefix is the values path whose image the chart renders; repository
// is that path's values.yaml default, against which the tag is resolved. The
// resolved digest and (for the cds self-entry) the full repo@digest reference
// are pinned under valuePrefix. resolveDigests pins both the repository and the
// digest it resolved against, so an operator's -f override of a repository
// cannot leave the chart deploying repoA@<digest-of-repoB>.
type c8sComponent struct {
	valuePrefix string // values path, e.g. "cds.image" (renders {repository}@{digest})
	repository  string // values.yaml default repository resolved against
	refKey      string // value key for the full repo@digest reference ("" if none)
}

// c8sComponents are the chart images c8s install pins to digests under
// --resolve-digests. Each repository must match the repository: field at the
// same values path in internal/helmchart/c8s/values.yaml. cds appears twice:
// once for the cds Deployment image (cds.image) and once for the nri push-hook
// / whitelist-seed self-entry (nriImagePolicy.cds.image), which the render
// guard requires.
var c8sComponents = []c8sComponent{
	{"image", "ghcr.io/lunal-dev/c8s-operator", ""},
	{"attestationService.image", "ghcr.io/lunal-dev/attestation-service", ""},
	{"cds.image", "ghcr.io/lunal-dev/cds", ""},
	{"ratlsMesh.image", "ghcr.io/lunal-dev/ratls-mesh", ""},
	{"nriImagePolicy.image", "ghcr.io/lunal-dev/nri-image-policy", ""},
	{"teeProxy.image", "ghcr.io/lunal-dev/tee-proxy", ""},
	{"nriImagePolicy.cds.image", "ghcr.io/lunal-dev/cds", "nriImagePolicy.cds.image.reference"},
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the c8s operator, CRDs, attestation-service, and component charts via Helm",
	Long: `Extracts the bundled c8s Helm chart and runs
'helm upgrade --install' against the current kubeconfig context. Deploys:

  - the install namespace (labeled pod-security=privileged when --kata is set)
  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-service DaemonSet (per-node /attest + /verify)
  - the CDS trust root (attestation, EAR issuance, mesh CA, leaf signing)
  - the ratls-mesh, nri-image-policy, tee-proxy, and tls-lb components

On RKE2 (--distro rke2) the kata-deploy and nri-image-policy DaemonSets carry
a containerd-prep initContainer that wires up the drop-in import; no node
preparation is required beyond a running cluster.

With --resolve-digests, each component image tag is resolved to its registry
digest (via the 'crane' CLI) and pinned, including the CDS digest the
image-policy floor and render guard require.

Requires the 'helm' and 'kubectl' CLIs to be on PATH ('crane' too when
--resolve-digests is set).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}

		dir, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract embedded chart: %w", err)
		}
		defer os.RemoveAll(dir)

		chartPath := filepath.Join(dir, helmchart.ChartRoot)
		imageTag := defaultInstallImageTag(version.Version)
		helmArgs := []string{
			"upgrade", "--install", installRelease, chartPath,
			"--namespace", installNamespace,
		}
		// Chart has no default image tags; chart images are released in lockstep
		// with the CLI, so pass the CLI's build version for every component.
		// Unstamped local builds report "dev"; fall back to the main branch tag
		// for that bootstrap path because CI does not publish a dev tag. The cds
		// self-entry (refKey set) shares cds.image's tag and has none of its own.
		for _, c := range c8sComponents {
			if c.refKey != "" {
				continue
			}
			helmArgs = append(helmArgs, "--set", c.valuePrefix+".tag="+imageTag)
		}
		helmArgs = appendInstallCRDArgs(helmArgs, installCRDs)
		helmArgs, err = appendDistroInstallArgs(helmArgs, installDistro)
		if err != nil {
			return err
		}
		helmArgs = appendKataInstallArgs(helmArgs, installKata, installKataEnforce)
		if installResolveDigests {
			helmArgs, err = appendResolvedDigestArgs(cmd.Context(), helmArgs, imageTag)
			if err != nil {
				return err
			}
		}
		if cmd.Flags().Changed("webhook-cert-fs-group") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.certVolume.fsGroup=%d", installCertFSGroup))
		}
		if cmd.Flags().Changed("webhook-cert-key-mode") {
			helmArgs = append(helmArgs, "--set-string", "webhook.certVolume.keyMode="+installCertKeyMode)
		}
		if cmd.Flags().Changed("webhook-get-cert-renew-interval") {
			helmArgs = append(helmArgs, "--set-string", "webhook.getCert.renewInterval="+installGetCertRenewInterval.String())
		}
		if cmd.Flags().Changed("webhook-get-cert-run-as-user") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.getCert.runAsUser=%d", installGetCertRunAsUser))
		}
		if cmd.Flags().Changed("webhook-get-cert-run-as-group") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.getCert.runAsGroup=%d", installGetCertRunAsGroup))
		}
		if cmd.Flags().Changed("webhook-get-cert-run-as-non-root") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.getCert.runAsNonRoot=%t", installGetCertRunAsNonRoot))
		}
		for _, vf := range installValues {
			helmArgs = append(helmArgs, "-f", vf)
		}
		if installWait {
			helmArgs = append(helmArgs, "--wait", "--timeout=5m")
		}

		// Only the kata stack ships privileged pods (kata-deploy DaemonSet);
		// without --kata, the c8s-system namespace can run under the default
		// pod-security baseline.
		privileged := installKata || installKataEnforce
		if err := applyNamespace(cmd.Context(), installNamespace, privileged); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
		hc := exec.CommandContext(cmd.Context(), "helm", helmArgs...)
		hc.Stdout = os.Stdout
		hc.Stderr = os.Stderr
		if err := hc.Run(); err != nil {
			return fmt.Errorf("helm install failed: %w", err)
		}

		fmt.Fprintln(os.Stdout)
		fmt.Fprint(os.Stdout, installNextSteps)
		return nil
	},
}

// extractChart writes the embedded chart tree to a fresh tmpdir and returns
// its path. Caller must RemoveAll when done.
func extractChart() (string, error) {
	dir, err := os.MkdirTemp("", "c8s-chart-*")
	if err != nil {
		return "", err
	}
	if err := os.CopyFS(dir, helmchart.ChartFS); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// applyNamespace creates the install namespace before helm. When privileged
// is true the namespace is labeled to allow privileged pods (kata-deploy);
// otherwise it is created without pod-security overrides. helm
// --create-namespace cannot set labels, so we always pre-apply.
func applyNamespace(ctx context.Context, namespace string, privileged bool) error {
	manifest, err := namespaceManifest(namespace, privileged)
	if err != nil {
		return fmt.Errorf("render namespace manifest: %w", err)
	}
	psa := "baseline"
	if privileged {
		psa = "privileged"
	}
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # Namespace/%s (pod-security=%s)\n", namespace, psa)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply namespace %q: %w", namespace, err)
	}
	return nil
}

// namespaceManifest renders the release Namespace as JSON (valid kubectl apply
// input). When privileged is true it sets pod-security labels at the enforce,
// warn, and audit modes; otherwise the namespace inherits the cluster default.
func namespaceManifest(namespace string, privileged bool) ([]byte, error) {
	ns := corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if privileged {
		ns.Labels = map[string]string{
			"pod-security.kubernetes.io/enforce": "privileged",
			"pod-security.kubernetes.io/warn":    "privileged",
			"pod-security.kubernetes.io/audit":   "privileged",
		}
	}
	return json.Marshal(ns)
}

// fallbackImageTag is installed whenever the build is not stamped with a
// release version. It is the branch every c8s component publishes; it is
// deliberately not "latest", which cds does not publish (so
// `crane digest ghcr.io/lunal-dev/cds:latest` under --resolve-digests would
// abort with MANIFEST_UNKNOWN).
const fallbackImageTag = "main"

// releaseVersion matches a clean release tag (vMAJOR.MINOR.PATCH), the only
// version for which CI publishes a matching image tag. A `git describe`
// derivative (e.g. v1.2.3-5-gabc, a bare commit SHA, or empty) has no published
// image, so defaultInstallImageTag falls back to fallbackImageTag.
var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// defaultInstallImageTag picks the image tag for an install: the build version
// when it is a published release tag, otherwise fallbackImageTag.
func defaultInstallImageTag(buildVersion string) string {
	if releaseVersion.MatchString(buildVersion) {
		return buildVersion
	}
	return fallbackImageTag
}

func appendInstallCRDArgs(helmArgs []string, installCRDs bool) []string {
	if installCRDs {
		return helmArgs
	}
	return append(helmArgs, "--skip-crds", "--set", "statusMirror.enabled=false")
}

// appendDistroInstallArgs validates --distro and translates it into the
// per-component host-distro values. It always applies: nri-image-policy
// installs regardless of --kata, and both it and kata-deploy must bind the
// containerd config layout the host distro uses.
func appendDistroInstallArgs(helmArgs []string, distro string) ([]string, error) {
	switch distro {
	case "k8s", "rke2":
	default:
		return nil, fmt.Errorf("--distro must be k8s or rke2, got %q", distro)
	}
	return append(helmArgs,
		"--set-string", "kata.distro="+distro,
		"--set-string", "nri-image-policy.distro="+distro,
	), nil
}

// appendKataInstallArgs translates the --kata / --kata-enforce flags into helm
// --set values. --kata-enforce implies --kata: enforcement is meaningless
// without the kata stack it injects and validates.
func appendKataInstallArgs(helmArgs []string, kata, enforce bool) []string {
	if !kata && !enforce {
		return helmArgs
	}
	helmArgs = append(helmArgs, "--set", "kata.enabled=true")
	if enforce {
		helmArgs = append(helmArgs, "--set", "kata.enforce.enabled=true")
	}
	return helmArgs
}

// craneDigest resolves an image reference to its registry digest by shelling
// out to `crane digest <ref>`. crane handles registry auth (docker config),
// manifest lists, and the v2 protocol — reimplementing that in-process would
// pull a heavyweight registry client for one lookup. The returned value is a
// bare "sha256:<hex>".
func craneDigest(ctx context.Context, ref string) (string, error) {
	out, err := exec.CommandContext(ctx, "crane", "digest", ref).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("crane digest %q: %w: %s", ref, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("crane digest %q: %w", ref, err)
	}
	digest := strings.TrimSpace(string(out))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("crane digest %q returned unexpected value %q", ref, digest)
	}
	return digest, nil
}

// appendResolvedDigestArgs resolves each chart component's repo:tag to its
// registry digest (via crane) and appends the helm --set flags that pin it.
func appendResolvedDigestArgs(ctx context.Context, helmArgs []string, tag string) ([]string, error) {
	if _, err := exec.LookPath("crane"); err != nil {
		return nil, fmt.Errorf("--resolve-digests needs the 'crane' CLI on PATH: %w", err)
	}
	return buildDigestArgs(helmArgs, tag, func(ref string) (string, error) {
		digest, err := craneDigest(ctx, ref)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stdout, "+ resolved %s -> %s\n", ref, digest)
		return digest, nil
	})
}

// buildDigestArgs appends, for every component, the --set flags that pin both
// its repository and the digest resolved against that repository. Pinning the
// repository too means an operator's -f override of a repository cannot leave
// the chart deploying repoA@<digest-of-repoB>: helm gives --set strict
// precedence over -f, so the repository and digest move together. The cds
// repository is resolved once and reused for cds.image and nriImagePolicy.cds.image
// so the two targets cannot diverge. Any resolution failure aborts: a
// partially-pinned floor would let the render guard pass while the served
// whitelist pointed at the wrong digest. The resolver is injected so the arg
// assembly is testable without a registry.
func buildDigestArgs(helmArgs []string, tag string, resolve func(ref string) (string, error)) ([]string, error) {
	cache := map[string]string{}
	for _, c := range c8sComponents {
		repo := c.repository
		ref := repo + ":" + tag
		digest, ok := cache[ref]
		if !ok {
			var err error
			digest, err = resolve(ref)
			if err != nil {
				return nil, err
			}
			cache[ref] = digest
		}
		helmArgs = append(helmArgs,
			"--set-string", c.valuePrefix+".repository="+repo,
			"--set-string", c.valuePrefix+".digest="+digest,
		)
		if c.refKey != "" {
			helmArgs = append(helmArgs, "--set-string", c.refKey+"="+repo+"@"+digest)
		}
	}
	return helmArgs, nil
}

const installNextSteps = `Next steps:

  1. Deploy this chart inside the intended CVM trust boundary. The supported
     install shape wires the chart-managed CDS trust root and
     attestation-service together.

  2. (Optional) Mirror status with a ConfidentialWorkload CR:

       kubectl apply -f samples/confidentialworkload.yaml

     When injection is enabled, annotate your workload's pod template:
       confidential.ai/cw: <workload-id>

  3. Inspect mirrored workloads:

       kubectl get cwl -A
`

func init() {
	installCmd.Flags().StringVar(&installNamespace, "namespace", "c8s-system", "namespace to install into")
	installCmd.Flags().StringVar(&installRelease, "release", "c8s", "Helm release name")
	installCmd.Flags().StringSliceVarP(&installValues, "values", "f", nil, "values files (repeatable)")
	installCmd.Flags().BoolVar(&installWait, "wait", true, "wait for the release to become ready (helm --wait)")
	installCmd.Flags().BoolVar(&installCRDs, "install-crds", true, "install chart CRDs (false passes helm --skip-crds)")
	installCmd.Flags().Int64Var(&installCertFSGroup, "webhook-cert-fs-group", 65532, "fsGroup for injected certificate volume")
	installCmd.Flags().StringVar(&installCertKeyMode, "webhook-cert-key-mode", "0640", "octal mode for injected tls.key")
	installCmd.Flags().DurationVar(&installGetCertRenewInterval, "webhook-get-cert-renew-interval", 6*time.Hour, "renewal interval for injected workload certificates")
	installCmd.Flags().Int64Var(&installGetCertRunAsUser, "webhook-get-cert-run-as-user", 65532, "runAsUser for injected get-cert containers")
	installCmd.Flags().Int64Var(&installGetCertRunAsGroup, "webhook-get-cert-run-as-group", 65532, "runAsGroup for injected get-cert containers")
	installCmd.Flags().BoolVar(&installGetCertRunAsNonRoot, "webhook-get-cert-run-as-non-root", true, "set runAsNonRoot for injected get-cert containers")
	installCmd.Flags().StringVar(&installDistro, "distro", "k8s", "host Kubernetes distro: k8s (vanilla/kubeadm) or rke2 — selects containerd config paths for kata and nri-image-policy")
	installCmd.Flags().BoolVar(&installKata, "kata", false, "install the Kata Containers runtime stack (kata-deploy DaemonSet + RuntimeClasses)")
	installCmd.Flags().BoolVar(&installKataEnforce, "kata-enforce", false, "enable kata enforcement: inject runtimeClasses into workload pods and reject non-kata RuntimeClasses (implies --kata)")
	installCmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", false, "resolve each c8s component image tag to its registry digest (via crane) and pin it, including the CDS digest the image-policy floor and render guard require")
	rootCmd.AddCommand(installCmd)
}
