package launchconfig

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewCmd returns the authenticated launch configuration command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "launch-config", Short: "Authenticate and stage a measured node's launch configuration"}
	var cfg Config
	stage := &cobra.Command{
		Use: "stage", Short: "Verify signed launch configuration and stage the selected node role",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := Stage(cmd.Context(), cfg); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "authenticated launch configuration staged")
			return nil
		},
	}
	f := stage.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "image TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", DefaultAttestationAPIURL, "trusted node-local attestation API")
	f.StringVar(&cfg.DocumentPath, "config", "", "required signed launch.yaml")
	f.StringVar(&cfg.SignaturePath, "signature", "", "required detached launch.yaml.sig")
	for _, name := range []string{"platform", "config", "signature"} {
		_ = stage.MarkFlagRequired(name)
	}
	cmd.AddCommand(stage)
	return cmd
}
