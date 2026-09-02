package allowlist

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newDigestCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "digest <file|->",
		Short: "Print the canonical SHA-256 of an allowlist file",
		Long: `Parse an allowlist file (or stdin with '-') and print the SHA-256 of its
canonical encoding — the digest CDS stamps into matched-workload leaves and,
under --static-allowlist, seals into the mesh CA certificate. This is the
value to pin with 'c8s verify --static-allowlist --allowlist <file>' and to
publish next to the allowlist (docs/static-allowlist.md). It reads only the
file; it never contacts CDS.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			al, err := pkgallowlist.ParseJSON(data)
			if err != nil {
				return err
			}
			digest, err := al.CanonicalDigest()
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"allowlist_digest": hex.EncodeToString(digest),
				})
			}
			fmt.Fprintln(cmd.OutOrStdout(), hex.EncodeToString(digest))
			return nil
		},
	}
}
