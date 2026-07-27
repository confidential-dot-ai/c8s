package allowlist

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newLintCmd(o *options) *cobra.Command {
	var online, strict bool
	cmd := &cobra.Command{
		Use:   "lint <file|->",
		Short: "Validate an allowlist file and report semantic warnings",
		Long: `Parse and validate an allowlist file (or stdin with '-') and report semantic
warnings: entries with no containers, a container that can never start, digests
whose effective policy is unconstrained, a digest that is floor-listed while also
carrying a workload policy (the floor short-circuits it), tag-form image labels
(TOCTOU), and root-subtree path grants. --online additionally checks each digest
exists in its registry via crane. --strict makes any warning exit non-zero.`,
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
			warnings := lintOffline(al)
			if online {
				if err := requireCrane(); err != nil {
					return err
				}
				warnings = append(warnings, lintOnline(ctx(cmd), al)...)
			}
			for _, w := range warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w)
			}
			if len(warnings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "ok: no warnings")
			}
			if strict && len(warnings) > 0 {
				cmd.SilenceErrors = true
				return fmt.Errorf("%d lint warning(s) with --strict", len(warnings))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&online, "online", false, "also check each digest exists in its registry via crane")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero if there are any warnings")
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
			if err := requireCrane(); err != nil {
				return err
			}
			ref := args[0]
			digest, err := craneDigest(ctx(cmd), ref)
			if err != nil {
				return err
			}
			cfg, err := craneConfig(ctx(cmd), ref)
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

// lintOffline reports semantic warnings for an allowlist without any registry or
// CDS access. The document is assumed already parsed/validated by ParseJSON.
func lintOffline(al *pkgallowlist.Allowlist) []string {
	var warnings []string
	anyCount := 0

	// digest -> set of distinct entry names; and whether some occurrence is
	// fully unconstrained (both argv segments any).
	entriesByDigest := map[string]map[string]bool{}
	fullyAny := map[string]bool{}

	for _, name := range sortedWorkloadNames(al.Workloads) {
		w := al.Workloads[name]
		if len(w.InitContainers) == 0 && len(w.Containers) == 0 {
			warnings = append(warnings, fmt.Sprintf("workload %q has no init or main containers", name))
		}
		if w.Label != "" && isTagForm(w.Label) {
			warnings = append(warnings, fmt.Sprintf("workload %q label %q is a tag, not a digest (informational, but tags are mutable — TOCTOU)", name, w.Label))
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
				warnings = append(warnings, fmt.Sprintf("workload %q container %s command is deny; the effective argv must be empty, so the container can never start", name, d))
			}
			if c.Command.Policy == pkgallowlist.PolicyAny {
				anyCount++
			}
			if c.Args.Policy == pkgallowlist.PolicyAny {
				anyCount++
			}
			if c.Paths.Policy == pkgallowlist.PolicyAny {
				anyCount++
			}
			if c.Image != "" && isTagForm(c.Image) {
				warnings = append(warnings, fmt.Sprintf("workload %q container %s image %q is a tag, not a digest (informational, but tags are mutable — TOCTOU)", name, d, c.Image))
			}
			for _, g := range append(append([]string{}, c.Paths.Read...), c.Paths.Write...) {
				if g == "/**" {
					warnings = append(warnings, fmt.Sprintf("workload %q container %s grants a root-subtree path %q (whole filesystem)", name, d, g))
				}
			}
		}
	}

	for _, d := range sortedKeysBool(fullyAny) {
		if len(entriesByDigest[d]) > 1 {
			warnings = append(warnings, fmt.Sprintf("digest %s appears in %d entries and one grants 'any'; the effective admission for that digest is 'any' (union across entries)", d, len(entriesByDigest[d])))
		}
	}

	// A floor digest is admitted by digest alone, so it short-circuits any argv
	// or paths policy an operator also wrote for the same digest in a workload.
	for _, d := range sortedKeys(al.Digests) {
		if names := entriesByDigest[d]; len(names) > 0 {
			warnings = append(warnings, fmt.Sprintf("digest %s is floor-listed and also in workload entr(ies) [%s]; the floor admits it by digest alone, so those argv/paths policies are not enforced (remove it from the floor to enforce them)", d, strings.Join(sortedKeysBool(names), ", ")))
		}
	}

	warnings = append(warnings, lintSecretsGrants(al)...)

	if anyCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 'any' (unconstrained) policy value(s) across all entries", anyCount))
	}
	return warnings
}

// lintSecretsGrants reports secrets-broker grant traps (docs/secrets-broker.md):
// grants behind permissive argv, grants outside the /secrets/ staging root,
// identical-set entries the broker must fail closed on, and within-entry
// duplicates that widen a digest's paths to 'any'.
func lintSecretsGrants(al *pkgallowlist.Allowlist) []string {
	var warnings []string

	setKeys := map[string][]string{} // canonical container-set key -> entry names
	grantsByEntry := map[string]bool{}
	for _, name := range sortedWorkloadNames(al.Workloads) {
		w := al.Workloads[name]
		entryHasGrants := false
		seenPerDigest := map[string][]pkgallowlist.Container{}
		for _, c := range allContainers(w) {
			d := c.Digest.String()
			seenPerDigest[d] = append(seenPerDigest[d], c)
			if c.Paths.Policy == pkgallowlist.PolicyDeny {
				continue
			}
			entryHasGrants = true
			if c.Command.Policy != pkgallowlist.PolicyExact || c.Args.Policy != pkgallowlist.PolicyExact {
				warnings = append(warnings, fmt.Sprintf("workload %q container %s carries path grants but its argv policy is not exact+exact — any invocation of these bytes can read the granted secrets", name, d))
			}
			for _, g := range append(append([]string{}, c.Paths.Read...), c.Paths.Write...) {
				if g != "/secrets/**" && !strings.HasPrefix(g, "/secrets/") {
					warnings = append(warnings, fmt.Sprintf("workload %q container %s grants path %q outside /secrets/ — the broker stages secrets only under /secrets/", name, d, g))
				}
			}
		}
		for d, cs := range seenPerDigest {
			if len(cs) > 1 {
				for _, c := range cs {
					if c.Paths.Policy == pkgallowlist.PolicyAny {
						warnings = append(warnings, fmt.Sprintf("workload %q duplicates digest %s and one occurrence widens paths to 'any'; the effective grant for that digest is any requested path (union within the entry)", name, d))
						break
					}
				}
			}
		}
		grantsByEntry[name] = entryHasGrants
		setKeys[containerSetKey(al, w)] = append(setKeys[containerSetKey(al, w)], name)
	}

	for _, names := range setKeys {
		if len(names) < 2 {
			continue
		}
		anyGrants := false
		for _, n := range names {
			anyGrants = anyGrants || grantsByEntry[n]
		}
		if anyGrants {
			warnings = append(warnings, fmt.Sprintf("entries [%s] share an identical container set while at least one carries path grants; the secrets broker fails closed on ambiguous entry resolution (403) for every pod of that set — differentiate the sets", strings.Join(names, ", ")))
		}
	}
	return warnings
}

// containerSetKey renders an entry's non-floor init/main digest sets as one
// comparable string. Entries with equal keys have identical claimed sets.
func containerSetKey(al *pkgallowlist.Allowlist, w pkgallowlist.Workload) string {
	set := func(cs []pkgallowlist.Container) []string {
		var out []string
		for _, c := range cs {
			d := c.Digest.String()
			if _, isFloor := al.Digests[d]; isFloor {
				continue
			}
			out = append(out, d)
		}
		sort.Strings(out)
		return out
	}
	return strings.Join(set(w.InitContainers), ",") + "|" + strings.Join(set(w.Containers), ",")
}

// lintOnline checks each workload container digest is resolvable in its
// registry via crane. It needs the container image label to know the repo.
func lintOnline(ctx context.Context, al *pkgallowlist.Allowlist) []string {
	var warnings []string
	checked := map[string]bool{}
	for _, name := range sortedWorkloadNames(al.Workloads) {
		w := al.Workloads[name]
		for _, c := range allContainers(w) {
			if c.Image == "" {
				warnings = append(warnings, fmt.Sprintf("workload %q container %s has no image label; cannot check the digest online", name, c.Digest))
				continue
			}
			named, err := reference.ParseDockerRef(c.Image)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("workload %q container %s image %q: %v", name, c.Digest, c.Image, err))
				continue
			}
			ref := reference.TrimNamed(named).String() + "@" + c.Digest.String()
			if checked[ref] {
				continue
			}
			checked[ref] = true
			if err := craneManifestExists(ctx, ref); err != nil {
				warnings = append(warnings, fmt.Sprintf("workload %q container digest not found in registry: %s (%v)", name, ref, err))
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
