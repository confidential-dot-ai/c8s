package allowlist

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newCanonicalizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "canonicalize <file|->",
		Short: "Write the canonical bytes for an allowlist file",
		Long: `Parse and validate an allowlist file, then write its canonical JSON bytes.
Use '-' to read stdin. This command is offline. It does not contact CDS.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			al, err := readAndParseAllowlist(cmd, args[0])
			if err != nil {
				return err
			}
			canonical, err := al.Canonical()
			if err != nil {
				return fmt.Errorf("canonicalize allowlist: %w", err)
			}
			_, err = cmd.OutOrStdout().Write(canonical)
			return err
		},
	}
}

func newDigestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "digest <file|->",
		Short: "Write the canonical SHA-256 digest for an allowlist file",
		Long: `Parse and validate an allowlist file, then write SHA-256 over its
canonical JSON bytes. Use '-' to read stdin. This command is offline. It does
not contact CDS.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			al, err := readAndParseAllowlist(cmd, args[0])
			if err != nil {
				return err
			}
			digest, err := al.CanonicalDigest()
			if err != nil {
				return fmt.Errorf("digest allowlist: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "sha256:%s\n", hex.EncodeToString(digest))
			return nil
		},
	}
}

func readAndParseAllowlist(cmd *cobra.Command, path string) (*pkgallowlist.Allowlist, error) {
	data, err := readFileOrStdin(cmd, path)
	if err != nil {
		return nil, err
	}
	al, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist %q: %w", path, err)
	}
	return al, nil
}
