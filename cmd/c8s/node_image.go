//go:build !c8s_node

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/version"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
)

const nodeImageNamespace = "c8s-system"

// nodeImageRenderConfig contains build inputs only. The role, endpoint and
// attested measurement policy are supplied by authenticated boot staging.
type nodeImageRenderConfig struct {
	platform        string
	kubeVersion     string
	imageDigest     string
	imageRepository string
	chartDir        string
	outputDir       string
}

func init() {
	rootCmd.AddCommand(newNodeImageCmd())
}

func newNodeImageCmd() *cobra.Command {
	var cfg nodeImageRenderConfig
	cmd := &cobra.Command{Use: "node-image", Short: "Build measured node-image integration artifacts"}
	render := &cobra.Command{
		Use:   "render",
		Short: "Render Kubernetes integration, nginx and the CDS seed at image build time",
		Long:  "Render the bundled chart with core services owned by systemd. Requires Helm at build time; no Helm is installed or run in the guest. Launch settings are read from the verified c8s-node-runtime ConfigMap at boot.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return renderNodeImage(cmd.Context(), cfg)
		},
	}
	f := render.Flags()
	f.StringVar(&cfg.platform, "hardware-platform", "", "CPU TEE: tdx or sev-snp (required)")
	f.StringVar(&cfg.kubeVersion, "kube-version", "", "Kubernetes semantic version from the baked RKE2 release (required)")
	f.StringVar(&cfg.imageDigest, "image-digest", "", "digest of the operator/get-cert container image (sha256:..., required)")
	f.StringVar(&cfg.imageRepository, "image-repository", "ghcr.io/confidential-dot-ai/c8s-operator", "operator/get-cert container repository")
	f.StringVar(&cfg.chartDir, "chart-dir", "", "chart source directory; empty uses the chart bundled in this binary")
	f.StringVar(&cfg.outputDir, "output-dir", "", "directory for c8s-integration.yaml, nginx.conf.in and allowlist-seed.json (required)")
	cmd.AddCommand(render)
	return cmd
}

var nodeImageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (cfg nodeImageRenderConfig) validate() error {
	if err := validateHardwarePlatform(cfg.platform); err != nil {
		return err
	}
	if _, err := version.ParseSemantic(cfg.kubeVersion); err != nil {
		return fmt.Errorf("--kube-version must specify the baked Kubernetes semantic version: %w", err)
	}
	if !nodeImageDigestPattern.MatchString(cfg.imageDigest) {
		return fmt.Errorf("--image-digest must be sha256 followed by 64 lowercase hexadecimal digits")
	}
	repo, err := reference.ParseNormalizedNamed(cfg.imageRepository)
	if err != nil {
		return fmt.Errorf("--image-repository: %w", err)
	}
	if _, tagged := repo.(reference.Tagged); tagged {
		return fmt.Errorf("--image-repository must not contain a tag")
	}
	if _, pinned := repo.(reference.Digested); pinned {
		return fmt.Errorf("--image-repository must not contain a digest; use --image-digest")
	}
	if cfg.outputDir == "" {
		return fmt.Errorf("--output-dir is required")
	}
	return nil
}

func renderNodeImage(ctx context.Context, cfg nodeImageRenderConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	chartDir := cfg.chartDir
	if chartDir == "" {
		tmp, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract node integration chart: %w", err)
		}
		defer os.RemoveAll(tmp)
		chartDir = filepath.Join(tmp, helmchart.ChartRoot)
	}
	args, err := appendCvmModeInstallArgs(nil, "node", cfg.platform)
	if err != nil {
		return err
	}
	args = appendDistroInstallArgs(args, "rke2")
	args = appendSingleNodeInstallArgs(args, true)
	args = append(args,
		"--set", "node.bakedServices=true",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "volumed.enabled=false",
		"--set", "router.attest.enabled=true",
		"--set", "router.nginx.httpsPort=443",
		"--set-string", "image.repository="+cfg.imageRepository,
		"--set-string", "image.digest="+cfg.imageDigest,
		"--set-string", "router.san[0]=c8s-node.invalid",
		"--set-string", "router.tlsMountPath=/run/c8s-tls",
		"--set-string", "router.discovery.mountPath=/run/c8s-tls",
	)
	args = append([]string{"template", "c8s", chartDir, "--namespace", nodeImageNamespace, "--kube-version", cfg.kubeVersion, "--include-crds"}, args...)
	helm := exec.CommandContext(ctx, "helm", args...)
	var stderr bytes.Buffer
	helm.Stderr = &stderr
	rendered, err := helm.Output()
	if err != nil {
		return fmt.Errorf("render node integration with helm: %w: %s", err, stderr.String())
	}
	integration, nginx, seed, err := splitNodeImageArtifacts(rendered)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	for _, artifact := range []struct {
		name string
		body []byte
	}{
		{"c8s-integration.yaml", integration},
		{"nginx.conf.in", nginx},
		{"allowlist-seed.json", seed},
	} {
		if err := os.WriteFile(filepath.Join(cfg.outputDir, artifact.name), artifact.body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", artifact.name, err)
		}
	}
	return nil
}

// splitNodeImageArtifacts keeps the chart as the single source for policies,
// nginx protections and the component allowlist. Render all templates so new
// admission policies are retained automatically, and reject unexpected workloads.
func splitNodeImageArtifacts(rendered []byte) (integration, nginx, seed []byte, err error) {
	namespace, err := namespaceManifest(nodeImageNamespace)
	if err != nil {
		return nil, nil, nil, err
	}
	var ns corev1.Namespace
	if err := yaml.Unmarshal(namespace, &ns); err != nil {
		return nil, nil, nil, err
	}
	ns.Labels["confidential.ai/baked"] = "true"
	namespace, err = yaml.Marshal(ns)
	if err != nil {
		return nil, nil, nil, err
	}
	var manifests bytes.Buffer
	manifests.Write(namespace)
	r := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(rendered)))
	operatorFound, crdFound := false, false
	for {
		doc, readErr := r.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, nil, nil, fmt.Errorf("read rendered chart: %w", readErr)
		}
		var object struct {
			metav1.TypeMeta `json:",inline"`
			Metadata        metav1.ObjectMeta `json:"metadata"`
		}
		if err := yaml.Unmarshal(doc, &object); err != nil {
			return nil, nil, nil, fmt.Errorf("decode rendered chart: %w", err)
		}
		if object.Kind == "" {
			continue
		}
		if object.Kind == "ConfigMap" {
			var cm corev1.ConfigMap
			if err := yaml.Unmarshal(doc, &cm); err != nil {
				return nil, nil, nil, fmt.Errorf("decode chart ConfigMap: %w", err)
			}
			switch cm.Name {
			case "c8s-router-nginx":
				if nginx != nil {
					return nil, nil, nil, fmt.Errorf("duplicate nginx ConfigMap")
				}
				nginx = []byte(cm.Data["nginx.conf"])
				continue
			case "c8s-cds-allowlist-seed":
				if seed != nil {
					return nil, nil, nil, fmt.Errorf("duplicate CDS allowlist-seed ConfigMap")
				}
				seed = []byte(cm.Data["allowlist-seed.json"])
				continue
			}
		}
		switch object.Kind {
		case "Deployment":
			if object.Metadata.Name != "c8s-operator" || operatorFound {
				return nil, nil, nil, fmt.Errorf("unexpected node-image Deployment %q", object.Metadata.Name)
			}
			operatorFound = true
		case "CustomResourceDefinition":
			crdFound = true
		case "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Service", "NetworkPolicy", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
		default:
			return nil, nil, nil, fmt.Errorf("unexpected node-image resource %s/%s", object.Kind, object.Metadata.Name)
		}
		manifests.WriteString("\n---\n")
		manifests.Write(doc)
	}
	if !operatorFound || !crdFound || len(nginx) == 0 || len(seed) == 0 {
		return nil, nil, nil, fmt.Errorf("rendered chart lacks required node-image operator, CRD, nginx configuration or CDS seed")
	}
	return manifests.Bytes(), nginx, seed, nil
}
