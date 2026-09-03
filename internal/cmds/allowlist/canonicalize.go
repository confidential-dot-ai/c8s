package allowlist

import (
	"fmt"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newCanonicalizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "canonicalize <file|->",
		Short: "Write an allowlist in its canonical JSON form",
		Long: `Parse an allowlist file, normalize it with the c8s schema, and write
the exact canonical JSON bytes used for policy digests. This command reads only
the file or stdin. It does not contact a cluster.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			document, err := pkgallowlist.ParseJSON(data)
			if err != nil {
				return err
			}
			canonical, err := document.Canonical()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(canonical))
			return err
		},
	}
}
