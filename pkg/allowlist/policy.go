package allowlist

import (
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Index answers admission queries for enforcers in O(1). Build it once from a
// normalized Allowlist.
type Index struct {
	floor    map[string]bool
	byDigest map[string][]indexedContainer
}

type indexedContainer struct {
	Container
	role string
}

// BuildIndex projects an Allowlist into an admission index.
func (a *Allowlist) BuildIndex() *Index {
	idx := &Index{
		floor:    make(map[string]bool, len(a.Digests)),
		byDigest: map[string][]indexedContainer{},
	}
	for d := range a.Digests {
		idx.floor[d] = true
	}
	for _, w := range a.Workloads {
		for _, c := range w.InitContainers {
			idx.byDigest[c.Digest.String()] = append(idx.byDigest[c.Digest.String()], indexedContainer{Container: c, role: ContainerRoleInit})
		}
		for _, c := range w.Containers {
			idx.byDigest[c.Digest.String()] = append(idx.byDigest[c.Digest.String()], indexedContainer{Container: c, role: ContainerRoleMain})
		}
	}
	return idx
}

// AdmitsDigest reports whether an image with this digest may run at all — as a
// floor digest, or as any workload container. It ignores argv, so it answers the
// coarse "are these bytes allowlisted" question the CDS issuance gate asks.
func (i *Index) AdmitsDigest(digest string) bool {
	d, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	if i.floor[d.String()] {
		return true
	}
	_, ok := i.byDigest[d.String()]
	return ok
}

// AdmitsContainer reports whether an observed container may run. Floor digests
// are admitted on the digest alone. For a workload digest, admission is the
// union across every entry that lists it: the observation must satisfy some
// declared container's argv, mount and env policy together.
func (i *Index) AdmitsContainer(r RunningContainer) bool {
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return false
	}
	if i.floor[d.String()] {
		return true
	}
	r.Digest = d.String()
	for _, c := range i.byDigest[d.String()] {
		if c.Container.admits(r) {
			return true
		}
	}
	return false
}

// MatchingRole returns the one declared init/main role that admits r. An empty
// result means the digest came from the floor, nothing matched, or different
// workload entries admit the same observation in different roles. Inventories
// carry the empty result so complete-set release fails safe for legacy entries
// whose role cannot be resolved.
func (i *Index) MatchingRole(r RunningContainer) string {
	d, err := types.ParseDigest(r.Digest)
	if err != nil || i.floor[d.String()] {
		return ""
	}
	r.Digest = d.String()
	role := ""
	for _, c := range i.byDigest[d.String()] {
		if !c.Container.admits(r) {
			continue
		}
		if role != "" && role != c.role {
			return ""
		}
		role = c.role
	}
	return role
}

// matchCommand matches a command policy against the front of argv. exact pins a
// prefix (argv must start with Argv) and returns the remaining args; any pins no
// prefix and passes the whole argv through; deny requires an empty argv.
func (p ArgvPolicy) matchCommand(argv []string, env map[string]string) (rest []string, ok bool) {
	switch p.Policy {
	case PolicyAny:
		return argv, true
	case PolicyDeny:
		return argv, len(argv) == 0
	case PolicyExact:
		expected, ok := p.boundArgv(env)
		if !ok || len(argv) < len(expected) {
			return nil, false
		}
		for i, tok := range expected {
			if argv[i] != tok {
				return nil, false
			}
		}
		return argv[len(expected):], true
	default:
		return nil, false
	}
}

// matchArgs matches an args policy against the argv left after the command:
// any accepts anything, deny requires none, exact requires equality.
func (p ArgvPolicy) matchArgs(rest []string, env map[string]string) bool {
	switch p.Policy {
	case PolicyAny:
		return true
	case PolicyDeny:
		return len(rest) == 0
	case PolicyExact:
		expected, ok := p.boundArgv(env)
		return ok && equalStrings(rest, expected)
	default:
		return false
	}
}

func (p ArgvPolicy) boundArgv(env map[string]string) ([]string, bool) {
	if len(p.EnvBindings) == 0 {
		return p.Argv, true
	}
	bound := slices.Clone(p.Argv)
	for _, binding := range p.EnvBindings {
		for _, name := range binding.Names {
			value, ok := env[name]
			if !ok || value == "" {
				return nil, false
			}
			bound[binding.Index] = strings.ReplaceAll(bound[binding.Index], "$("+name+")", value)
		}
	}
	return bound, true
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
