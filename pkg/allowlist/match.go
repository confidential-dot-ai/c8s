package allowlist

import "fmt"

// RunningContainer is one container as an enforcer observes it: the bytes, the
// effective argv they were told to run, the destinations of its BIND mounts
// (the ones that can carry host-supplied content in), and its environment
// variable names without values.
//
// A local type rather than the inventory's own keeps this package a pure
// function of the allowlist — the caller converts.
//
// An enforcer that cannot observe a field leaves it nil, which an exact policy
// treats as "nothing to refuse" rather than as a violation. The in-guest
// policy-monitor reads the guest OCI spec and fills all four; the host-side NRI
// plugin gates images on a node CVM and fills Digest and Argv only.
type RunningContainer struct {
	Digest     string
	Argv       []string
	BindMounts []string
	EnvNames   []string
}

// ErrNoMatch reports that no entry describes the running set; ErrAmbiguous that
// more than one does. Both are refusals, but they say different things to an
// operator: the first is a set that matches nothing, the second a pair of
// entries that cannot be told apart.
var (
	ErrNoMatch   = fmt.Errorf("allowlist: no workload entry matches the running containers")
	ErrAmbiguous = fmt.Errorf("allowlist: more than one workload entry matches the running containers")
)

// MatchWorkload resolves a running container set to the single entry that
// describes it.
//
// An entry matches when every running container is one it declares (digest and
// argv), and every main container it declares is running. It is deliberately not
// set equality: a declared init container may have exited, and a declared native
// sidecar keeps running, so demanding the two sets be equal would refuse
// ordinary pods outright. "Nothing foreign, every main present" admits both
// while still refusing a set containing anything the entry does not name.
//
// running must already have had injected-component containers removed — this
// package does not know which images the platform injects.
//
// Argv is matched against the entry's own policies rather than via Index, whose
// admission is a union across every entry listing a digest: an entry pinning an
// exact command guarantees nothing here if another entry widens the same digest.
func (a *Allowlist) MatchWorkload(running []RunningContainer) (string, Workload, error) {
	if len(running) == 0 {
		// A pod always runs at least the container that is asking, so an empty
		// set is no evidence rather than a set that happens to match an entry
		// declaring nothing.
		return "", Workload{}, ErrNoMatch
	}
	var (
		foundName string
		found     Workload
		matches   int
	)
	for name, w := range a.Workloads {
		if !w.describes(running) {
			continue
		}
		matches++
		if matches > 1 {
			return "", Workload{}, ErrAmbiguous
		}
		foundName, found = name, w
	}
	if matches == 0 {
		return "", Workload{}, ErrNoMatch
	}
	return foundName, found, nil
}

// EntryDiff is the distance between an entry and a running set: what is running
// that the entry does not name, and what it declares as a main that nothing
// running satisfies. Both empty means the entry describes the set.
type EntryDiff struct {
	// Foreign is running containers no declared container admits — the ⊆ half.
	Foreign []RunningContainer
	// MissingMains is declared main containers nothing running satisfies — the
	// ⊇ half. An init container is absent from this by design: a declared init
	// may have exited.
	MissingMains []Container
}

// Describes reports whether the entry matches.
func (d EntryDiff) Describes() bool { return len(d.Foreign) == 0 && len(d.MissingMains) == 0 }

// Diff evaluates an entry against a running set without short-circuiting, so a
// near miss can be reported in full.
//
// This is the release decision itself, not a reconstruction of it: describes is
// Diff().Describes(), so a diagnostic built on this cannot disagree with what
// CDS actually did.
func (w Workload) Diff(running []RunningContainer) EntryDiff {
	declared := make([]Container, 0, len(w.Containers)+len(w.InitContainers))
	declared = append(declared, w.Containers...)
	declared = append(declared, w.InitContainers...)

	var d EntryDiff
	for _, r := range running {
		if !admittedBy(declared, r) {
			d.Foreign = append(d.Foreign, r)
		}
	}
	for _, c := range w.Containers {
		if !anyRunning(running, c) {
			d.MissingMains = append(d.MissingMains, c)
		}
	}
	return d
}

// describes reports whether the entry admits everything running and has all its
// main containers present.
func (w Workload) describes(running []RunningContainer) bool {
	return w.Diff(running).Describes()
}

// admittedBy reports whether some declared container permits this running
// container's digest and argv.
func admittedBy(declared []Container, r RunningContainer) bool {
	for _, c := range declared {
		if c.admits(r) {
			return true
		}
	}
	return false
}

// anyRunning reports whether a declared container is satisfied by something
// running.
func anyRunning(running []RunningContainer, c Container) bool {
	for _, r := range running {
		if c.admits(r) {
			return true
		}
	}
	return false
}

// admits reports whether this declared container permits the running one.
func (c Container) admits(r RunningContainer) bool {
	if c.Digest.String() != r.Digest {
		return false
	}
	rest, ok := c.Command.matchCommand(r.Argv)
	if !ok || !c.Args.matchArgs(rest) {
		return false
	}
	return c.Mounts.admits(r.BindMounts) && c.Env.admits(r.EnvNames)
}

// admits reports whether every bind destination is one this policy names.
func (p MountPolicy) admits(destinations []string) bool {
	if p.Policy != PolicyExact {
		return true
	}
	return everyIn(destinations, p.Destinations)
}

// admits reports whether every environment name is one this policy names.
func (p EnvPolicy) admits(names []string) bool {
	if p.Policy != PolicyExact {
		return true
	}
	return everyIn(names, p.Names)
}

// everyIn reports whether every observed value appears in allowed. An empty
// observation is vacuously true — see RunningContainer on enforcers that cannot
// see a field.
func everyIn(observed, allowed []string) bool {
	if len(observed) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for _, o := range observed {
		if _, ok := set[o]; !ok {
			return false
		}
	}
	return true
}
