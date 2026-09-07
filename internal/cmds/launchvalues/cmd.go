package launchvalues

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// NewCmd returns the `c8s launch-values` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "launch-values",
		Short: "Render launch-time HelmChartConfig values for the c8s node image",
	}
	cmd.AddCommand(newRenderCmd())
	return cmd
}

// helmChartConfig is the wire shape c8s-chart-values.sh (now a thin wrapper,
// see node-guest-image/c8s/mkosi.extra/usr/local/bin/c8s-chart-values.sh)
// used to build by hand with shell indentation. RKE2's supervisor merges
// this into the matching baked HelmChart c8s's spec (see
// node-guest-image/c8s/c8s-chart.<platform>.yaml.in); the mechanism is
// documented there and in docs/operator.md, "Launch-time values".
type helmChartConfig struct {
	APIVersion string              `yaml:"apiVersion"`
	Kind       string              `yaml:"kind"`
	Metadata   helmChartConfigMeta `yaml:"metadata"`
	Spec       helmChartConfigSpec `yaml:"spec"`
}

type helmChartConfigMeta struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type helmChartConfigSpec struct {
	// ValuesContent carries Render's own output verbatim: it is already
	// valid YAML, and re-decoding it into `any` here would risk a
	// round-trip that reorders or retypes a value Render deliberately chose
	// (e.g. a hex measurement string that happens to parse as a number).
	ValuesContent yaml.Node `yaml:"valuesContent"`
}

func newRenderCmd() *cobra.Command {
	var cfg Config
	var out string
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Render the c8s HelmChartConfig for this boot",
		Long: `render builds the HelmChartConfig c8s-chart-values.sh writes to RKE2's
manifests dir, failing closed on any error rather than writing a partial or
unpinned one. See internal/cmds/launchvalues's package doc for the trust
chain and docs/operator.md, "Launch-time values", for the fragment shape and
allowlist.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			valuesContent, err := Render(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			if out == "" {
				_, err = fmt.Fprint(cmd.OutOrStdout(), valuesContent)
				return err
			}
			manifest, err := renderHelmChartConfigManifest(valuesContent)
			if err != nil {
				return err
			}
			if err := writeAtomic(out, manifest, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", DefaultAttestationAPIURL, "local attestation-api base URL (SNP self-measurement)")
	f.StringVar(&cfg.FragmentPath, "fragment", "", "opkeydata values.yaml fragment (optional; omit to render only the boot-derived tree)")
	f.StringVar(&cfg.SignaturePath, "signature", "", "detached signature for --fragment (c8s keys sign-values output; required when --fragment is set)")
	f.StringVar(&out, "out", "", "write the full HelmChartConfig manifest here instead of the bare values tree to stdout")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}

// renderHelmChartConfigManifest wraps valuesContent (Render's output) in the
// fixed HelmChartConfig header and marshals the whole object in one shot —
// no hand-built indentation, unlike the shell heredoc this command replaces.
func renderHelmChartConfigManifest(valuesContent string) ([]byte, error) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(valuesContent), &node); err != nil {
		return nil, fmt.Errorf("parse rendered values: %w", err)
	}
	// yaml.Unmarshal into a yaml.Node produces a DocumentNode wrapping the
	// real root; helmChartConfigSpec.ValuesContent wants that root, block-
	// styled so it renders as a literal block scalar's contents, i.e. an
	// ordinary nested mapping under valuesContent: rather than a folded flow
	// scalar.
	root := &node
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		root = node.Content[0]
	}
	cfg := helmChartConfig{
		APIVersion: "helm.cattle.io/v1",
		Kind:       "HelmChartConfig",
		Metadata:   helmChartConfigMeta{Name: "c8s", Namespace: "kube-system"},
		Spec:       helmChartConfigSpec{ValuesContent: *root},
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal HelmChartConfig: %w", err)
	}
	header := "# Rendered at boot by c8s-chart-values.service — DO NOT EDIT.\n" +
		"# Launch-time inputs the baked HelmChart c8s (c8s-chart.yaml) cannot carry\n" +
		"# itself. RKE2 merges this into that HelmChart's spec; see\n" +
		"# node-guest-image/c8s/mkosi.extra/usr/local/bin/c8s-chart-values.sh and\n" +
		"# internal/cmds/launchvalues.\n"
	return append([]byte(header), out...), nil
}

// writeAtomic writes data to path via a same-directory temp file + rename,
// so a reader (RKE2's deploy controller watching this manifest) never
// observes a partial write — the same atomicity c8s-chart-values.sh's own
// TMP-then-mv gave when it built this file by hand.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".launch-values-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}
