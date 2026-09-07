package launchvalues

import (
	"fmt"

	"github.com/spf13/cobra"
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

func newRenderCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Render the c8s HelmChartConfig valuesContent for this boot",
		Long: `render builds the values tree c8s-chart-values.sh writes as
spec.valuesContent of the boot HelmChartConfig: this guest's own launch
measurement and RTMR pins, plus the operator key loaded and verified through
credrelease.LoadMeasuredOperatorKey (the same launch-bound key
cred-release.service trusts).

With --fragment, an opkeydata values.yaml carrying deployment configuration
(tls-lb hostnames/CORS, cds.dnsSanPatterns, rate limits, image-policy exempt
namespaces and bootstrap digests, ...) is verified against --signature under
the measured operator key, checked to name this guest's own --own-measurement,
validated leaf-by-leaf against an explicit allowlist, and deep-merged UNDER
the boot-derived keys so it can never override them. Without --fragment, only
the boot-derived tree is printed.

Fails closed: any error here must stop the boot, not render a partial or
unpinned HelmChartConfig.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := Render(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), out)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", DefaultAttestationAPIURL, "local attestation-api base URL (SNP self-measurement)")
	f.StringVar(&cfg.OperatorPubkeyPath, "operator-pubkey", DefaultOperatorPubkeyPath, "initrd-staged operator public key path (existence check only — the trusted read goes through credrelease.LoadMeasuredOperatorKey)")
	f.StringVar(&cfg.FragmentPath, "fragment", "", "opkeydata values.yaml fragment (optional; omit to render only the boot-derived tree)")
	f.StringVar(&cfg.SignaturePath, "signature", "", "detached signature for --fragment (c8s keys sign-values output; required when --fragment is set)")
	f.StringVar(&cfg.OwnMeasurementHex, "own-measurement", "", "this guest's own launch measurement, hex (required)")
	f.StringSliceVar(&cfg.RTMRs, "rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> (repeatable/comma-separated; empty on SNP)")
	_ = cmd.MarkFlagRequired("platform")
	_ = cmd.MarkFlagRequired("own-measurement")
	return cmd
}
