package keys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
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
		Long: `Sign a launch-time values fragment for opkeydata: ECDSA (P-256) over the
SHA-256 of the file's exact bytes, ASN.1 DER, base64-encoded, written as a
single line to <values.yaml>.sig next to it.

'c8s launch-values render' on the guest verifies this signature against the
operator public key the guest already trusts (the same key measured into
its launch identity) before trusting anything in the fragment — see
internal/cmds/launchvalues.`,
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
	sig, err := signValues(key, data)
	if err != nil {
		return err
	}
	sigPath := valuesPath + signValuesSuffix
	if err := writeNew(sigPath, sig, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", sigPath)
	return nil
}

// signValues signs sha256(data) with key, ASN.1 DER, base64-encoded with a
// trailing newline — the exact wire format 'c8s launch-values render'
// parses back.
func signValues(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	line := base64.StdEncoding.EncodeToString(der)
	return []byte(line + "\n"), nil
}
