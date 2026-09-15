package secrets

import (
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newPutCmd(o *options) *cobra.Command {
	var (
		fromFile  string
		overwrite bool
		dryRun    bool
		meshCA    string
		force     bool
	)
	cmd := &cobra.Command{
		Use:   "put <path>",
		Short: "Store an operator-supplied value at a secret path",
		Long: `Store a value at <path> in the CDS secret store, reading it from stdin or from
--from-file. The bytes are stored exactly as read, including any trailing
newline; the byte count is printed so you can confirm which bytes were sent.

A path that already holds a value needs --overwrite, and the value it holds is
named before it is replaced.

The write names the CDS it trusts with --mesh-ca: the mesh CA CDS serves must be
one you pinned, or the secret is refused. --force writes without that check.

A workload reads its secret into a file once, at startup. Replacing a value
reaches a running pod when that pod next restarts.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			path, err := pkgallowlist.CanonicalSecretPath(args[0])
			if err != nil {
				return err
			}
			value, err := readValue(cmd, fromFile)
			if err != nil {
				return err
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would write %d bytes to %s\n", len(value), path)
				return nil
			}

			c, err := o.client(cmd.Context())
			if err != nil {
				return err
			}
			if err := gateOnMeshCA(cmd, c, o.URL, meshCA, force); err != nil {
				return err
			}

			signer, err := o.Signer()
			if err != nil {
				return err
			}

			// Ask to create first, whatever --overwrite says. A path that already
			// holds a value comes back refused with what is there, so the line
			// naming what a replacement destroys is printed before it happens —
			// the store has no versioning and no delete.
			res, err := c.put(cmd.Context(), path, value, false, signer)
			if err != nil {
				return err
			}
			if res.Created {
				fmt.Fprintf(cmd.OutOrStdout(), "+ %s (new)\n", path)
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s\n", len(value), path)
				return nil
			}
			if !overwrite {
				return fmt.Errorf("%s already holds %s; re-run with --overwrite to replace it", path, describe(res.Existing))
			}

			fmt.Fprintf(cmd.OutOrStdout(), "~ %s (replaces %s)\n", path, describe(res.Existing))
			res, err = c.put(cmd.Context(), path, value, true, signer)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s\n", len(value), path)
			if res.Existing == intsecrets.OriginWorkload {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"note: pods already holding the workload-generated value keep it until they restart\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the value from this file instead of stdin")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace a value already at the path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the intended change without calling CDS")
	cmd.Flags().StringVar(&meshCA, "mesh-ca", "", "PEM bundle of the mesh CA this CDS must serve; the same anchor 'c8s verify --mesh-ca' takes. Required unless --force")
	cmd.Flags().BoolVar(&force, "force", false, "write the secret without checking the CDS mesh CA against --mesh-ca. Unrelated to --overwrite, which governs replacing an existing value")
	return cmd
}

// gateOnMeshCA refuses a write whose CDS is not pinned to an operator-held mesh
// CA. A plaintext endpoint is exempt for the same reason it is exempt from the
// measurement pin: --insecure has already announced that nothing about the peer
// is authenticated, and /ca fetched over it would be the host's answer anyway.
func gateOnMeshCA(cmd *cobra.Command, c client, rawURL, meshCA string, force bool) error {
	if u, err := url.Parse(rawURL); err == nil && u.Scheme == "http" {
		return nil
	}
	if force {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"warning: --force: writing this secret without checking the CDS mesh CA. An attested peer at this address that is not your CDS receives the value.")
		return nil
	}
	if meshCA == "" {
		return errMeshCARequired
	}
	return c.verifyMeshCA(cmd.Context(), meshCA)
}

// describe names a stored value by what put it there, for the line an operator
// reads before replacing it.
func describe(o intsecrets.Origin) string {
	switch o {
	case intsecrets.OriginWorkload:
		return "a workload-generated value"
	case intsecrets.OriginOperator:
		return "an operator-supplied value"
	default:
		return "a value"
	}
}

// readValue reads the secret from a file or stdin. The bytes are passed through
// unmodified: a PEM key ends in a newline and a token usually must not, so
// neither can be trimmed on the CLI's guess.
func readValue(cmd *cobra.Command, fromFile string) ([]byte, error) {
	var (
		value []byte
		err   error
	)
	if fromFile != "" {
		value, err = os.ReadFile(fromFile)
		if err != nil {
			return nil, fmt.Errorf("read --from-file: %w", err)
		}
	} else {
		value, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read value from stdin: %w", err)
		}
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("value is empty: supply it on stdin or with --from-file")
	}
	return value, nil
}
