package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
)

func newExternalCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "external",
		Short: "Manage the external KMS backend",
		Long: `Connect the CDS secret store to an external KMS: mapped paths are fetched
from it at release time instead of held by CDS. One backend is configured at
a time; azure-keyvault is the supported backend.

'apply' replaces the whole backend atomically with a JSON document read from
--file or stdin:

  {
    "schema": "c8s.secrets-external/v1",
    "backend": "azure-keyvault",
    "credential": {"tenantId": "…", "clientId": "…", "clientSecret": "…"},
    "mappings": {"/tenant-a/hf-token": {"vault": "https://v.vault.azure.net", "name": "hf-token"}}
  }

The credential reaches CDS over the attested channel and lives in CDS memory
only — never in a Kubernetes resource — so a CDS restart clears it. The mapping
set is persisted beside the allowlist database, so after a restart mapped paths
fail closed until the credential is re-applied. Apply an empty document
("mappings": {} and no credential) to disconnect the vault.

Workload access is unchanged: a mapped path still needs an allowlist grant, and
the workload receives the vault value's bytes verbatim — base64 a binary key
vault-side if the workload expects raw bytes.`,
		SilenceUsage: true,
	}
	cmd.AddCommand(newExternalApplyCmd(o), newExternalStatusCmd(o))
	return cmd
}

func newExternalApplyCmd(o *options) *cobra.Command {
	var fromFile string
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Replace the Azure backend config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			doc, err := readExternalDoc(cmd, fromFile)
			if err != nil {
				return err
			}
			signer, err := o.Signer()
			if err != nil {
				return err
			}
			c, err := o.client(cmd.Context())
			if err != nil {
				return err
			}
			st, err := c.putExternal(cmd.Context(), doc, signer)
			if err != nil {
				return err
			}
			printExternalStatus(cmd.OutOrStdout(), st)
			return nil
		},
	}
	cmd.Flags().StringVarP(&fromFile, "file", "f", "", "read the config document from this file instead of stdin")
	return cmd
}

func newExternalStatusCmd(o *options) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the Azure backend state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			signer, err := o.Signer()
			if err != nil {
				return err
			}
			c, err := o.client(cmd.Context())
			if err != nil {
				return err
			}
			st, err := c.getExternal(cmd.Context(), signer)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			printExternalStatus(cmd.OutOrStdout(), st)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the raw report")
	return cmd
}

// readExternalDoc reads the config document from a file or stdin. The bytes pass
// through unmodified; CDS validates.
func readExternalDoc(cmd *cobra.Command, fromFile string) ([]byte, error) {
	var (
		doc []byte
		err error
	)
	if fromFile != "" {
		doc, err = os.ReadFile(fromFile)
		if err != nil {
			return nil, fmt.Errorf("read --file: %w", err)
		}
	} else {
		doc, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read document from stdin: %w", err)
		}
	}
	if len(strings.TrimSpace(string(doc))) == 0 {
		return nil, fmt.Errorf("document is empty: supply it on stdin or with --file")
	}
	return doc, nil
}

// printExternalStatus renders the backend state. The credential and fetched
// values are never in it.
func printExternalStatus(w io.Writer, st intsecrets.ExternalStatus) {
	if len(st.Mappings) == 0 {
		fmt.Fprintln(w, "no azure mappings: the vault backend is off")
		return
	}
	if st.Configured {
		fmt.Fprintln(w, "credential applied")
	} else {
		fmt.Fprintln(w, "NO CREDENTIAL: mapped paths fail closed until 'c8s secrets external apply'")
	}
	paths := make([]string, 0, len(st.Mappings))
	for p := range st.Mappings {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		m := st.Mappings[p]
		fmt.Fprintf(w, "%s -> %s/secrets/%s\n", p, m.Vault, m.Name)
		if r, ok := st.LastFetch[p]; ok {
			if r.Err == "" {
				fmt.Fprintf(w, "    last fetch ok at %s\n", r.At.Format("2006-01-02 15:04:05Z07:00"))
			} else {
				fmt.Fprintf(w, "    last fetch FAILED at %s: %s\n", r.At.Format("2006-01-02 15:04:05Z07:00"), r.Err)
			}
		}
	}
	for _, p := range st.Shadowed {
		fmt.Fprintf(w, "warning: %s shadows a value held in the CDS store; unmapping exposes it again\n", p)
	}
}
