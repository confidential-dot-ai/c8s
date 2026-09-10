package allowlist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

func newGetCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Print one entry as canonical JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			al, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			w, ok := al.Workloads[args[0]]
			if !ok {
				return fmt.Errorf("no workload entry named %q", args[0])
			}
			return writeJSON(cmd.OutOrStdout(), w)
		},
	}
}

func newApplyCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply <file|->",
		Short: "Upsert entries from a file (whole-entry replace)",
		Long: `Upsert each entry in <file> (or stdin with '-'). The file is either a full or
partial allowlist document or a name-keyed map of entries. Each entry is
replaced whole — this never field-merges into a live entry.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			data, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			entries, err := parseWorkloadEntries(data)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("no workload entries in %q", args[0])
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, _, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}

			entries, err = parseWorkloadEntriesForSchema(data, live.Schema)
			if err != nil {
				return err
			}
			findings := lintOffline(&pkgallowlist.Allowlist{Schema: live.Schema, Workloads: entries})
			// The ambiguity check is the one finding that cannot be made from
			// the file alone: the entry it collides with is usually one already
			// served. Only pairs that span both are added here, since a
			// collision inside the file is already reported above.
			findings = append(findings, collisionsWithLive(entries, live)...)
			for _, f := range findings {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", f)
			}
			if errs := countErrors(findings); errs > 0 {
				return fmt.Errorf("refusing to apply: %d lint error(s)", errs)
			}

			names := slices.Sorted(maps.Keys(entries))
			for _, name := range names {
				if lw, ok := live.Workloads[name]; ok {
					ed := diffEntry(lw, entries[name])
					if ed.empty() {
						fmt.Fprintf(cmd.OutOrStdout(), "= %s (unchanged)\n", name)
						continue
					}
					fmt.Fprintf(cmd.OutOrStdout(), "~ %s\n", name)
					printEntryDiff(cmd.OutOrStdout(), ed)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "+ %s (new)\n", name)
				}
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would upsert %d workload entr(ies)\n", len(entries))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			for _, name := range names {
				if err := c.PutWorkload(ctx(cmd), name, entries[name], signer); err != nil {
					return fmt.Errorf("put workload %q: %w", name, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "applied %s\n", name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without writing any entry")
	return cmd
}

func newEditCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "edit <name>",
		Short: "Fetch an entry, edit it in $EDITOR, and apply the result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			name := args[0]
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, _, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			orig, ok := live.Workloads[name]
			if !ok {
				return fmt.Errorf("no workload entry named %q", name)
			}

			edited, err := editWorkloadInEditor(orig, name, live.Schema)
			if err != nil {
				return err
			}
			if diffEntry(orig, *edited).empty() {
				fmt.Fprintln(cmd.ErrOrStderr(), "no changes")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "~ %s\n", name)
			printEntryDiff(cmd.OutOrStdout(), diffEntry(orig, *edited))

			if !confirm(cmd, fmt.Sprintf("apply changes to %q?", name)) {
				fmt.Fprintln(cmd.ErrOrStderr(), "aborted")
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.PutWorkload(ctx(cmd), name, *edited, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "applied %s\n", name)
			return nil
		},
	}
}

func newDeleteCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name> [<name>...]",
		Short: "Delete one or more entries",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			for _, name := range args {
				if err := c.DeleteWorkload(ctx(cmd), name, signer); err != nil {
					var se *allowlistclient.StatusError
					if errors.As(err, &se) && se.Status == 404 {
						return fmt.Errorf("no workload entry named %q", name)
					}
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", name)
			}
			return nil
		},
	}
}

// collisionsWithLive reports entries being applied that no running set could
// tell apart from an entry already served, which would refuse both. Groups
// entirely inside the applied set are left out: lintOffline over the file has
// already named those.
func collisionsWithLive(entries map[string]pkgallowlist.Workload, live *pkgallowlist.Allowlist) []finding {
	merged := make(map[string]pkgallowlist.Workload, len(live.Workloads)+len(entries))
	for name, w := range live.Workloads {
		merged[name] = w
	}
	for name, w := range entries {
		merged[name] = w
	}
	groups, err := indistinguishableGroups(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: merged})
	if err != nil {
		return []finding{errorf("workload entries could not be compared with the served allowlist: %v", err)}
	}
	var out []finding
	for _, names := range groups {
		applied, served := 0, 0
		for _, n := range names {
			if _, ok := entries[n]; ok {
				applied++
			} else {
				served++
			}
		}
		if applied > 0 && served > 0 {
			out = append(out, ambiguousGroupFinding(names))
		}
	}
	for _, pair := range shadowPairs(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: merged}) {
		_, wideApplied := entries[pair[0]]
		_, narrowApplied := entries[pair[1]]
		if wideApplied != narrowApplied {
			out = append(out, shadowFinding(pair[0], pair[1]))
		}
	}
	return out
}

// --- shared helpers ---

// parseWorkloadEntries accepts either a full/partial allowlist document or a
// bare name-keyed map of workload entries.
func parseWorkloadEntries(data []byte) (map[string]pkgallowlist.Workload, error) {
	return parseWorkloadEntriesForSchema(data, "")
}

func parseWorkloadEntriesForSchema(data []byte, schema string) (map[string]pkgallowlist.Workload, error) {
	if al, perr := pkgallowlist.ParseJSON(data); perr == nil {
		if schema != "" && schema != al.Schema {
			return nil, fmt.Errorf("document schema differs from CDS; use allowlist upload for an explicit whole-document migration")
		}
		if al.Workloads == nil {
			al.Workloads = map[string]pkgallowlist.Workload{}
		}
		return al.Workloads, nil
	}

	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&raw); derr != nil {
		return nil, fmt.Errorf("parse workload entries: not an allowlist document or a name-keyed workload map: %w", derr)
	}
	out := make(map[string]pkgallowlist.Workload, len(raw))
	for name, body := range raw {
		w, werr := pkgallowlist.ParseWorkloadJSONForSchema(body, schema)
		if werr != nil {
			return nil, fmt.Errorf("workload %q: %w", name, werr)
		}
		out[name] = *w
	}
	return out, nil
}

func readFileOrStdin(cmd *cobra.Command, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(cmd.InOrStdin())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

// editWorkloadInEditor writes the entry to a temp file, opens $EDITOR (vi if
// unset) on it, and re-validates the result via ParseWorkloadJSON.
func editWorkloadInEditor(w pkgallowlist.Workload, name string, schema ...string) (*pkgallowlist.Workload, error) {
	tmp, err := os.CreateTemp("", "c8s-workload-"+sanitizeFileName(name)+"-*.json")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	defer os.Remove(path)

	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	if err := runEditor(path); err != nil {
		return nil, err
	}
	edited, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(schema) > 0 {
		return pkgallowlist.ParseWorkloadJSONForSchema(edited, schema[0])
	}
	return pkgallowlist.ParseWorkloadJSON(edited)
}

func runEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if strings.TrimSpace(editor) == "" {
		editor = "vi"
	}
	fields := strings.Fields(editor)
	args := append(fields[1:], path)
	c := exec.Command(fields[0], args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("editor %q: %w", editor, err)
	}
	return nil
}

func sanitizeFileName(name string) string {
	return strings.Map(func(r rune) rune {
		if isSafeFileNameRune(r) {
			return r
		}
		return '_'
	}, name)
}

func isSafeFileNameRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

func confirm(cmd *cobra.Command, prompt string) bool {
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
