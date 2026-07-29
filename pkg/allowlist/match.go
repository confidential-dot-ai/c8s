package allowlist

import "fmt"

// RunningContainer is one container an inventory reports: the bytes, and the
// effective argv they were told to run.
//
// A local type rather than the inventory's own keeps this package a pure
// function of the allowlist — the caller converts.
type RunningContainer struct {
	Digest string
	Argv   []string
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

// describes reports whether the entry admits everything running and has all its
// main containers present.
func (w Workload) describes(running []RunningContainer) bool {
	declared := make([]Container, 0, len(w.Containers)+len(w.InitContainers))
	declared = append(declared, w.Containers...)
	declared = append(declared, w.InitContainers...)

	for _, r := range running {
		if !admittedBy(declared, r) {
			return false
		}
	}
	for _, c := range w.Containers {
		if !anyRunning(running, c) {
			return false
		}
	}
	return true
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
	return ok && c.Args.matchArgs(rest)
}
