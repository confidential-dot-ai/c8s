package allowlist

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newLintCmd(o *options) *cobra.Command {
	var online, strict bool
	var cvmMode string
	cmd := &cobra.Command{
		Use:   "lint <file|->",
		Short: "Validate an allowlist file and report semantic warnings",
		Long: `Parse and validate an allowlist file (or stdin with '-') and report semantic
findings: entries with no containers, a container that can never start, digests
whose effective policy is unconstrained, a digest that is floor-listed while also
carrying a workload policy (the floor short-circuits it), tag-form image labels
(TOCTOU), root-subtree path grants, and mount/env policy on a deployment whose
enforcer cannot observe those fields. --online additionally checks each digest
exists in its registry via crane.

Two entries declaring the same containers with the same argv policy are an
error: release requires exactly one entry to match, so both are refused
forever. Errors exit non-zero on their own; --strict makes warnings do the
same.`,
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
			findings := lintOffline(al)
			findings = append(findings, unobservedFieldPolicies(al, cvmMode)...)
			if online {
				if err := crane.Require(); err != nil {
					return err
				}
				findings = append(findings, lintOnline(ctx(cmd), al)...)
			}
			for _, f := range findings {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", f)
			}
			if len(findings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "ok: no findings")
			}
			if errs := countErrors(findings); errs > 0 {
				cmd.SilenceErrors = true
				return fmt.Errorf("%d lint error(s)", errs)
			}
			if strict && len(findings) > 0 {
				cmd.SilenceErrors = true
				return fmt.Errorf("%d lint warning(s) with --strict", len(findings))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&online, "online", false, "also check each digest exists in its registry via crane")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero if there are any warnings")
	cmd.Flags().StringVar(&cvmMode, "cvm-mode", "", "install shape the allowlist targets (pod, node-cloud, node-metal, node-image); pod silences the mount/env scope warning")
	return cmd
}

func newInspectImageCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect-image <ref>",
		Short: "Show an image's resolved digest and baked Entrypoint/Cmd (viewer only)",
		Long: `Resolve an image reference via crane and print its digest plus the image's
default Entrypoint and Cmd, so you can see the baked argv before writing an exact
policy. This reads the registry only; it never contacts CDS.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := crane.Require(); err != nil {
				return err
			}
			ref := args[0]
			digest, err := crane.Digest(ctx(cmd), ref)
			if err != nil {
				return err
			}
			cfg, err := crane.Config(ctx(cmd), ref)
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"ref":        ref,
					"digest":     digest,
					"entrypoint": cfg.Config.Entrypoint,
					"cmd":        cfg.Config.Cmd,
				})
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "ref:        %s\n", ref)
			fmt.Fprintf(w, "digest:     %s\n", digest)
			fmt.Fprintf(w, "entrypoint: %s\n", shellJoin(cfg.Config.Entrypoint))
			fmt.Fprintf(w, "cmd:        %s\n", shellJoin(cfg.Config.Cmd))
			return nil
		},
	}
}

// finding is one lint result.
//
// An error is a document that cannot work rather than a judgement an operator
// may accept, so it fails a lint whatever --strict says and blocks a write.
type finding struct {
	err bool
	msg string
}

func (f finding) String() string {
	if f.err {
		return "error: " + f.msg
	}
	return "warning: " + f.msg
}

func warnf(format string, args ...any) finding {
	return finding{msg: fmt.Sprintf(format, args...)}
}

func errorf(format string, args ...any) finding {
	return finding{err: true, msg: fmt.Sprintf(format, args...)}
}

// countErrors reports how many findings are errors.
func countErrors(findings []finding) int {
	n := 0
	for _, f := range findings {
		if f.err {
			n++
		}
	}
	return n
}

// lintOffline reports semantic findings for an allowlist without any registry or
// CDS access. The document is assumed already parsed/validated by ParseJSON.
func lintOffline(al *pkgallowlist.Allowlist) []finding {
	var warnings []finding
	anyCount := 0

	// digest -> set of distinct entry names; and whether some occurrence is
	// fully unconstrained (both argv segments any).
	entriesByDigest := map[string]map[string]bool{}
	fullyAny := map[string]bool{}

	for _, name := range sortedWorkloadNames(al.Workloads) {
		w := al.Workloads[name]
		if len(w.InitContainers) == 0 && len(w.Containers) == 0 {
			warnings = append(warnings, warnf("workload %q has no init or main containers", name))
		}
		if w.Label != "" && isTagForm(w.Label) {
			warnings = append(warnings, warnf("workload %q label %q is a tag, not a digest (informational, but tags are mutable — TOCTOU)", name, w.Label))
		}
		for _, c := range allContainers(w) {
			d := c.Digest.String()
			if entriesByDigest[d] == nil {
				entriesByDigest[d] = map[string]bool{}
			}
			entriesByDigest[d][name] = true
			if c.Command.Policy == pkgallowlist.PolicyAny && c.Args.Policy == pkgallowlist.PolicyAny {
				fullyAny[d] = true
			}
			if argvPolicyName(c.Command) == pkgallowlist.PolicyDeny {
				warnings = append(warnings, warnf("workload %q container %s command is deny; the effective argv must be empty, so the container can never start", name, d))
			}
			if c.Command.Policy == pkgallowlist.PolicyAny {
				anyCount++
			}
			if c.Args.Policy == pkgallowlist.PolicyAny {
				anyCount++
			}
			if c.Image != "" && isTagForm(c.Image) {
				warnings = append(warnings, warnf("workload %q container %s image %q is a tag, not a digest (informational, but tags are mutable — TOCTOU)", name, d, c.Image))
			}
		}
		if w.Secrets != nil {
			for _, g := range append(append([]string{}, w.Secrets.Read...), w.Secrets.Write...) {
				if g == "/**" {
					warnings = append(warnings, warnf("workload %q grants the root secret subtree %q (every secret in the store)", name, g))
				}
			}
		}
	}

	for _, d := range sortedKeysBool(fullyAny) {
		if len(entriesByDigest[d]) > 1 {
			warnings = append(warnings, warnf("digest %s appears in %d entries and one grants 'any'; the effective admission for that digest is 'any' (union across entries)", d, len(entriesByDigest[d])))
		}
	}

	// A floor digest is admitted by digest alone, so it short-circuits any argv
	// policy an operator also wrote for the same digest in a workload — and for
	// a secrets-bearing entry it also makes the entry unmatchable, since the
	// digest is dropped from the candidate set.
	for _, d := range sortedKeys(al.Digests) {
		if names := entriesByDigest[d]; len(names) > 0 {
			warnings = append(warnings, warnf("digest %s is floor-listed and also in workload entr(ies) [%s]; the floor admits it by digest alone, so those argv policies are not enforced (remove it from the floor to enforce them)", d, strings.Join(sortedKeysBool(names), ", ")))
		}
	}

	warnings = append(warnings, indistinguishableEntries(al)...)

	if anyCount > 0 {
		warnings = append(warnings, warnf("%d 'any' (unconstrained) policy value(s) across all entries", anyCount))
	}
	return warnings
}

// unobservedFieldPolicies reports mount and env policy that the deployment's
// enforcer cannot see. Only the in-guest policy-monitor reads the guest OCI
// spec; the host NRI plugin sees the CRI container, reports neither field, and
// an unobserved field is vacuously satisfied — so outside pod mode such a
// policy admits every container with no signal at write, install or deny time.
func unobservedFieldPolicies(al *pkgallowlist.Allowlist, cvmMode string) []finding {
	if cvmMode == "pod" {
		return nil
	}
	var warnings []finding
	for _, name := range sortedWorkloadNames(al.Workloads) {
		for _, c := range allContainers(al.Workloads[name]) {
			var fields []string
			if c.Mounts.Policy == pkgallowlist.PolicyExact {
				fields = append(fields, "mounts")
			}
			if c.Env.Policy == pkgallowlist.PolicyExact {
				fields = append(fields, "env")
			}
			if fields == nil {
				continue
			}
			warnings = append(warnings, warnf("workload %q container %s constrains %s; only the in-guest policy-monitor observes those fields, so on a deployment enforced by the host NRI plugin this policy admits every container (pass --cvm-mode=pod if this allowlist targets kata)", name, c.Digest.String(), strings.Join(fields, " and ")))
		}
	}
	return warnings
}

// indistinguishableEntries reports entries that no running set can tell apart.
//
// Release requires exactly one entry to describe the containers a sandbox runs,
// so entries with the same shape both match or neither does — the match is
// ambiguous forever and every pod resolving to them is refused, whichever grant
// an operator meant. Nothing a workload can do fixes it, so this is an error.
func indistinguishableEntries(al *pkgallowlist.Allowlist) []finding {
	groups, err := indistinguishableGroups(al)
	if err != nil {
		return []finding{errorf("workload entries could not be compared: %v", err)}
	}
	out := make([]finding, 0, len(groups))
	for _, names := range groups {
		out = append(out, ambiguousGroupFinding(names))
	}
	return out
}

// indistinguishableGroups returns each set of two or more entry names sharing a
// shape, in a stable order.
func indistinguishableGroups(al *pkgallowlist.Allowlist) ([][]string, error) {
	byShape := map[string][]string{}
	for _, name := range sortedWorkloadNames(al.Workloads) {
		shape, err := entryShape(al.Workloads[name])
		if err != nil {
			// A shape that will not marshal cannot be compared; say so rather
			// than silently treating the entry as unique.
			return nil, fmt.Errorf("workload %q: %w", name, err)
		}
		byShape[shape] = append(byShape[shape], name)
	}
	var out [][]string
	for _, shape := range sortedKeysStrings(byShape) {
		if names := byShape[shape]; len(names) > 1 {
			out = append(out, names)
		}
	}
	return out, nil
}

func ambiguousGroupFinding(names []string) finding {
	return errorf(
		"workloads [%s] declare the same containers with the same argv policy; release requires exactly one entry to match, so all of them are refused (merge them, or narrow the argv policy so a running pod resolves to one)",
		strings.Join(names, ", "))
}

// entryShape is the part of an entry a release decision reads: the digests and
// argv policies of each container list. Image labels and the secret grant are
// excluded — two entries differing only in those are exactly the dangerous
// case, since the grant an operator intended is the thing that never resolves.
func entryShape(w pkgallowlist.Workload) (string, error) {
	type containerShape struct {
		Digest  string                  `json:"digest"`
		Command pkgallowlist.ArgvPolicy `json:"command"`
		Args    pkgallowlist.ArgvPolicy `json:"args"`
	}
	shape := func(cs []pkgallowlist.Container) ([]string, error) {
		out := make([]string, 0, len(cs))
		for _, c := range cs {
			b, err := json.Marshal(containerShape{Digest: c.Digest.String(), Command: c.Command, Args: c.Args})
			if err != nil {
				return nil, err
			}
			out = append(out, string(b))
		}
		// Sorted so declaration order is not mistaken for a difference.
		sort.Strings(out)
		return out, nil
	}
	mains, err := shape(w.Containers)
	if err != nil {
		return "", err
	}
	inits, err := shape(w.InitContainers)
	if err != nil {
		return "", err
	}
	// The two lists stay distinct: a main is required to be present and an init
	// is not, so moving a container between them changes what matches.
	b, err := json.Marshal([][]string{mains, inits})
	return string(b), err
}

func sortedKeysStrings(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lintOnline checks each workload container digest is resolvable in its
// registry via crane. It needs the container image label to know the repo.
func lintOnline(ctx context.Context, al *pkgallowlist.Allowlist) []finding {
	var warnings []finding
	checked := map[string]bool{}
	for _, name := range sortedWorkloadNames(al.Workloads) {
		w := al.Workloads[name]
		for _, c := range allContainers(w) {
			if c.Image == "" {
				warnings = append(warnings, warnf("workload %q container %s has no image label; cannot check the digest online", name, c.Digest))
				continue
			}
			named, err := reference.ParseDockerRef(c.Image)
			if err != nil {
				warnings = append(warnings, warnf("workload %q container %s image %q: %v", name, c.Digest, c.Image, err))
				continue
			}
			ref := reference.TrimNamed(named).String() + "@" + c.Digest.String()
			if checked[ref] {
				continue
			}
			checked[ref] = true
			if err := crane.ManifestExists(ctx, ref); err != nil {
				warnings = append(warnings, warnf("workload %q container digest not found in registry: %s (%v)", name, ref, err))
			}
		}
	}
	return warnings
}

// isTagForm reports whether an image reference carries a tag rather than a
// digest. A parse failure is treated as not-a-tag (the label is informational).
func isTagForm(image string) bool {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return false
	}
	_, digested := named.(reference.Digested)
	return !digested
}

func sortedKeysBool(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
