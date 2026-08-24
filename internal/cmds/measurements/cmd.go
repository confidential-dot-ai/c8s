// Package measurements implements the `c8s measurements` command group:
// deriving a measurements config from built images, and checking one.
package measurements

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/spf13/cobra"
)

// NewCmd returns the `c8s measurements` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "measurements",
		Short: "Work with measurements config files",
		Long: "A measurements config pins the VM images a cluster accepts. Each entry is one\n" +
			"image, matched as a whole: a launch digest together with the runtime registers\n" +
			"measured from the same build.",
	}
	cmd.AddCommand(newDeriveCmd(), newLintCmd())
	return cmd
}

func newLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <measurements.json>",
		Short: "Check a measurements config for problems",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := measurements.Load(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok: %s, %d image(s)\n", set.TEE, len(set.Entries))
			for _, e := range set.Entries {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d register pin(s)\n", e.Name, len(e.RTMRs))
			}
			return nil
		},
	}
}
