package keys

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// signValuesSuffix is appended to the values file path to name its
// signature file. `c8s launch-values render` (internal/cmds/launchvalues)
// looks for exactly this name next to the fragment on the opkeydata disk.
const signValuesSuffix = ".sig"

// newSignValuesCmd returns the `c8s keys sign-values` subcommand.
func newSignValuesCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "sign-values <values.yaml>",
		Short: "Sign a launch-time values fragment with the operator private key",
		Long: `Sign a launch-time values fragment for opkeydata, writing the detached
signature to <values.yaml>.sig next to it. See docs/operator.md,
"Launch-time values", for the fragment shape and how 'c8s launch-values
render' verifies it on the guest.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return fmt.Errorf("--key is required: the operator private key PEM")
			}
			return runSignValues(cmd, keyPath, args[0])
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "operator private key PEM (c8s keys new --out)")
	return cmd
}

func runSignValues(cmd *cobra.Command, keyPath, valuesPath string) error {
	key, err := certutil.LoadECPrivateKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("load operator key: %w", err)
	}
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", valuesPath, err)
	}
	line, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	sigPath := valuesPath + signValuesSuffix
	if err := writeNew(sigPath, []byte(line+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", sigPath)
	return nil
}
