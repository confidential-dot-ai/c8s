package allowlist

import (
	"fmt"
	"maps"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Roles of a container inside a workload entry. The role is part of a rule's
// identity: moving a container between the init and main lists changes when
// its permissions apply.
const (
	RoleInit = "init"
	RoleMain = "main"
)

// Index answers admission queries for enforcers in O(1). Build it once, from a
// normalized Allowlist (BuildIndex) or from a bare digest set (DigestIndex). A
// nil *Index admits nothing, so an enforcer with no policy yet can query it
// without a guard.
type Index struct {
	byDigest map[string][]Match
}

// Match names the declared rule that admits an observation: the entry it came
// from, the container list (role) it was declared in, the container policy
// itself, and the entry's secret grant. An enforcer needs all four to name the
// rule a running instance was admitted under.
type Match struct {
	Workload  string
	Role      string
	Container Container
	Secrets   *SecretsPolicy
}

// BuildIndex projects an Allowlist into an admission index.
//
// Entries are walked in name order so the candidate list of a digest two
// entries share is the same on every node: MatchContainer returns the first
// candidate that admits, and nodes must agree on which rule that is.
func (a *Allowlist) BuildIndex() *Index {
	idx := &Index{byDigest: map[string][]Match{}}
	for _, name := range slices.Sorted(maps.Keys(a.Workloads)) {
		w := a.Workloads[name]
		for _, list := range []struct {
			role       string
			containers []Container
		}{{RoleInit, w.InitContainers}, {RoleMain, w.Containers}} {
			for _, c := range list.containers {
				d := c.Digest.String()
				idx.byDigest[d] = append(idx.byDigest[d], Match{Workload: name, Role: list.role, Container: c, Secrets: w.Secrets})
			}
		}
	}
	return idx
}

// DigestIndex builds an index that admits each digest whatever it runs — the
// shape of a DigestEntry, without a document to carry one. The bootstrap layers
// are its callers: the NRI plugin's always_allow set and the guest monitor's
// baked seed both sit beside a pulled snapshot rather than inside it, so a
// withheld or failed pull cannot drop them.
//
// Digests arrive in the forms enforcers see (types.NormalizeDigest). One that
// does not normalize is skipped and named in warnings, which leaves the caller
// to decide whether a single bad entry is fatal.
func DigestIndex(digests []string) (*Index, []error) {
	idx := &Index{byDigest: map[string][]Match{}}
	var warnings []error
	for _, raw := range digests {
		d, err := types.NormalizeDigest(raw)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("skip digest %q: %w", raw, err))
			continue
		}
		idx.byDigest[d.String()] = []Match{{Container: Container{
			Digest:  d,
			Command: ArgvPolicy{Policy: PolicyAny},
			Args:    ArgvPolicy{Policy: PolicyAny},
		}}}
	}
	return idx, warnings
}

// Size reports how many distinct digests the index lists. Enforcers log it to
// say how much policy is in force.
func (i *Index) Size() int {
	if i == nil {
		return 0
	}
	return len(i.byDigest)
}

// AdmitsDigest reports whether an image with this digest may run at all — as
// any workload container. It ignores argv, so it answers the coarse "are these
// bytes allowlisted" question the CDS issuance gate asks.
func (i *Index) AdmitsDigest(digest string) bool {
	if i == nil {
		return false
	}
	d, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	_, ok := i.byDigest[d.String()]
	return ok
}

// AdmitsContainer reports whether an observed container may run. Admission is
// the union across every entry that lists the digest: the observation must
// satisfy some declared container's argv, mount and env policy together.
func (i *Index) AdmitsContainer(r RunningContainer) bool {
	_, ok := i.MatchContainer(r)
	return ok
}

// MatchContainer returns the rule that admits r, or ok false when none does.
// It is AdmitsContainer with the winning candidate named, which is what an
// enforcer needs to record what an instance was admitted under; the bool
// contract of AdmitsContainer stays as it was.
//
// A digest listed by several entries has several candidates. The first that
// admits wins, in the deterministic order BuildIndex established.
func (i *Index) MatchContainer(r RunningContainer) (Match, bool) {
	if i == nil {
		return Match{}, false
	}
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return Match{}, false
	}
	r.Digest = d.String()
	for _, m := range i.byDigest[r.Digest] {
		if m.Container.admits(r) {
			return m, true
		}
	}
	return Match{}, false
}

// matchCommand matches a command policy against the front of argv. exact pins a
// prefix (argv must start with Argv) and returns the remaining args; any pins no
// prefix and passes the whole argv through; deny requires an empty argv.
func (p ArgvPolicy) matchCommand(argv []string) (rest []string, ok bool) {
	switch p.Policy {
	case PolicyAny:
		return argv, true
	case PolicyDeny:
		return argv, len(argv) == 0
	case PolicyExact:
		if len(argv) < len(p.Argv) {
			return nil, false
		}
		for i, tok := range p.Argv {
			if argv[i] != tok {
				return nil, false
			}
		}
		return argv[len(p.Argv):], true
	default:
		return nil, false
	}
}

// matchArgs matches an args policy against the argv left after the command:
// any accepts anything, deny requires none, exact requires equality.
func (p ArgvPolicy) matchArgs(rest []string) bool {
	switch p.Policy {
	case PolicyAny:
		return true
	case PolicyDeny:
		return len(rest) == 0
	case PolicyExact:
		return equalStrings(rest, p.Argv)
	default:
		return false
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AdmitsProcess is the preliminary NRI create-time check. It deliberately checks
// only digest/argv; a successful result MUST be followed by AdmitsContainer on
// the finalized OCI spec before start, and must never authorize secret release.
func (i *Index) AdmitsProcess(r RunningContainer) bool {
	if i == nil {
		return false
	}
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return false
	}
	r.Digest = d.String()
	for _, m := range i.byDigest[r.Digest] {
		if m.Container.admitsProcess(r) {
			return true
		}
	}
	return false
}
