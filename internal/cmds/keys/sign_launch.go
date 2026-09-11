package keys

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// signLaunchSuffix is appended to the values file path to name its
// signature file. `c8s launch-config stage` (internal/cmds/launchconfig)
// looks for exactly this name next to the document on the opkeydata disk.
const signLaunchSuffix = ".sig"

// newSignLaunchCmd returns the `c8s keys sign-launch` subcommand.
func newSignLaunchCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "sign-launch <launch.yaml>",
		Short: "Sign a launch configuration with the operator private key",
		Long: `Sign a launch configuration for opkeydata, writing the detached
signature to <launch.yaml>.sig next to it. See docs/operator.md,
"Authenticated launch configuration", for the schema and how
'c8s launch-config stage' verifies it on the guest.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return fmt.Errorf("--key is required: the operator private key PEM")
			}
			return runSignLaunch(cmd, keyPath, args[0])
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "operator private key PEM (c8s keys new --out)")
	return cmd
}

func runSignLaunch(cmd *cobra.Command, keyPath, launchPath string) error {
	key, err := certutil.LoadECPrivateKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("load operator key: %w", err)
	}
	data, err := os.ReadFile(launchPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", launchPath, err)
	}
	line, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	sigPath := launchPath + signLaunchSuffix
	if err := writeNew(sigPath, []byte(line+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", sigPath)
	return nil
}
