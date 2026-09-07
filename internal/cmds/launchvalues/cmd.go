package launchvalues

import (
	"fmt"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
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

// helmChartConfig is the helm.cattle.io/v1 HelmChartConfig RKE2's deploy
// controller merges into the baked HelmChart c8s's spec (see
// node-guest-image/c8s/c8s-chart.<platform>.yaml.in and docs/operator.md,
// "Launch-time values").
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
	// ValuesContent is a string in the CRD, not a mapping: Render's YAML
	// output is carried verbatim as a block scalar and parsed by
	// helm-controller. Embedding it as a nested mapping is rejected by the
	// apiserver, which would leave the baked chart installed unpinned.
	ValuesContent string `yaml:"valuesContent"`
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
			// Atomic: RKE2's deploy controller watches this directory and
			// must never observe a partial manifest.
			if err := fileutil.WriteAtomic(out, manifest, 0o644); err != nil {
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
// fixed HelmChartConfig header.
func renderHelmChartConfigManifest(valuesContent string) ([]byte, error) {
	cfg := helmChartConfig{
		APIVersion: "helm.cattle.io/v1",
		Kind:       "HelmChartConfig",
		Metadata:   helmChartConfigMeta{Name: "c8s", Namespace: "kube-system"},
		Spec:       helmChartConfigSpec{ValuesContent: valuesContent},
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
