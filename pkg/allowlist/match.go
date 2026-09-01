package allowlist

import "fmt"

// RunningContainer is one container as an enforcer observes it: the bytes, the
// effective argv they were told to run, the destinations of its BIND mounts
// (the ones that can carry host-supplied content in), and its environment
// variable names. EnvValues contains only public argv-binding values.
//
// A local type rather than the inventory's own keeps this package a pure
// function of the allowlist — the caller converts.
//
// MountsObserved and EnvObserved distinguish an observed empty set from a
// field the enforcer cannot see. An exact policy fails closed when its field
// was not observed. An Any policy does not require the observation.
type RunningContainer struct {
	Name           string
	Role           string
	Stopped        bool
	Digest         string
	Argv           []string
	BindMounts     []string
	BindMountKinds map[string]string
	EnvNames       []string
	// EnvValues contains only public values that an exact argv policy can bind.
	// A missing value also represents an ambiguous duplicate CRI environment
	// name and makes that binding fail closed.
	EnvValues      map[string]string
	MountsObserved bool
	EnvObserved    bool
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
// running must contain every observed container, including platform-injected
// helpers. Omitting helpers would let a digest-floor c8s image run an
// attacker-selected command without changing the matched workload identity.
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
	// CardinalityMismatch means each item matched in isolation, but no one-to-one
	// assignment could cover every observation and every declared main.
	CardinalityMismatch bool
}

// Describes reports whether the entry matches.
func (d EntryDiff) Describes() bool {
	return len(d.Foreign) == 0 && len(d.MissingMains) == 0 && !d.CardinalityMismatch
}

// Diff evaluates an entry against a running set without short-circuiting, so a
// near miss can be reported in full.
//
// This is the release decision itself, not a reconstruction of it: describes is
// Diff().Describes(), so a diagnostic built on this cannot disagree with what
// CDS actually did.
func (w Workload) Diff(running []RunningContainer) EntryDiff {
	declared := make([]declaredContainer, 0, len(w.Containers)+len(w.InitContainers))
	for _, c := range w.Containers {
		declared = append(declared, declaredContainer{Container: c, role: ContainerRoleMain, allowUnknownRole: roleUnique(w.InitContainers, c)})
	}
	for _, c := range w.InitContainers {
		declared = append(declared, declaredContainer{Container: c, role: ContainerRoleInit, allowUnknownRole: roleUnique(w.Containers, c)})
	}

	var d EntryDiff
	for _, r := range running {
		if !admittedBy(declared, r) {
			d.Foreign = append(d.Foreign, r)
		}
	}
	for _, c := range w.Containers {
		if !anyRunning(running, declaredContainer{Container: c, role: ContainerRoleMain, allowUnknownRole: roleUnique(w.InitContainers, c)}) {
			d.MissingMains = append(d.MissingMains, c)
		}
	}
	if len(d.Foreign) == 0 && len(d.MissingMains) == 0 && !hasCompleteAssignment(declared, running) {
		d.CardinalityMismatch = true
	}
	return d
}

func roleUnique(opposite []Container, target Container) bool {
	if target.Name != "" {
		return true
	}
	for _, other := range opposite {
		if other.Name == "" && other.Digest == target.Digest && policyKey(other) == policyKey(target) {
			return false
		}
	}
	return true
}

// describes reports whether the entry admits everything running and has all its
// main containers present.
func (w Workload) describes(running []RunningContainer) bool {
	return w.Diff(running).Describes()
}

// admittedBy reports whether some declared container permits this running
// container's digest and argv.
type declaredContainer struct {
	Container
	role             string
	allowUnknownRole bool
}

func admittedBy(declared []declaredContainer, r RunningContainer) bool {
	for _, c := range declared {
		if c.matches(r) {
			return true
		}
	}
	return false
}

// anyRunning reports whether a declared container is satisfied by something
// running.
func anyRunning(running []RunningContainer, c declaredContainer) bool {
	for _, r := range running {
		if c.satisfies(r) {
			return true
		}
	}
	return false
}

func (c declaredContainer) matches(r RunningContainer) bool {
	if !c.Container.admits(r) {
		return false
	}
	if r.Role != "" && r.Role != c.role {
		return false
	}
	// A named declaration is its own role discriminator on runtimes whose CRI
	// surface cannot state init versus main. An unnamed legacy declaration needs
	// an explicit resolved role; otherwise a stopped init could satisfy a main.
	return r.Role != "" || c.Name != "" || c.allowUnknownRole
}

// satisfies adds the liveness rule used for required declarations. A stopped
// item remains a valid historical observation, but it cannot prove that a main
// container is running now. Completed init containers remain optional.
func (c declaredContainer) satisfies(r RunningContainer) bool {
	return c.matches(r) && (c.role != ContainerRoleMain || !r.Stopped)
}

// hasCompleteAssignment proves two conditions with one-to-one edges: every
// declared main has one observation, and every observation has one declaration.
// Init declarations are optional because a completed init can be absent. The
// second phase can displace an earlier match, but it never leaves a main empty.
func hasCompleteAssignment(declared []declaredContainer, running []RunningContainer) bool {
	if len(running) < countRole(declared, ContainerRoleMain) || len(running) > len(declared) {
		return false
	}
	declToRun := make([]int, len(declared))
	for i := range declToRun {
		declToRun[i] = -1
	}
	runToDecl := make([]int, len(running))
	for i := range runToDecl {
		runToDecl[i] = -1
	}

	// Cover every main first.
	for di, c := range declared {
		if c.role != ContainerRoleMain {
			continue
		}
		seenRun := make([]bool, len(running))
		if !assignMain(di, declared, running, declToRun, runToDecl, seenRun) {
			return false
		}
	}
	// Cover every remaining observation. Reassignment keeps each occupied main
	// occupied and can move its prior observation to an init declaration.
	for ri := range running {
		if runToDecl[ri] >= 0 {
			continue
		}
		seenDecl := make([]bool, len(declared))
		if !assignRunning(ri, declared, running, declToRun, runToDecl, seenDecl) {
			return false
		}
	}
	return true
}

func countRole(declared []declaredContainer, role string) int {
	n := 0
	for _, c := range declared {
		if c.role == role {
			n++
		}
	}
	return n
}

func assignMain(di int, declared []declaredContainer, running []RunningContainer, declToRun, runToDecl []int, seenRun []bool) bool {
	for ri, r := range running {
		if seenRun[ri] || !declared[di].satisfies(r) {
			continue
		}
		seenRun[ri] = true
		prior := runToDecl[ri]
		if prior < 0 || assignMain(prior, declared, running, declToRun, runToDecl, seenRun) {
			declToRun[di] = ri
			runToDecl[ri] = di
			return true
		}
	}
	return false
}

func assignRunning(ri int, declared []declaredContainer, running []RunningContainer, declToRun, runToDecl []int, seenDecl []bool) bool {
	for di, c := range declared {
		if seenDecl[di] || !c.satisfies(running[ri]) {
			continue
		}
		seenDecl[di] = true
		priorRun := declToRun[di]
		if priorRun < 0 || assignRunning(priorRun, declared, running, declToRun, runToDecl, seenDecl) {
			declToRun[di] = ri
			runToDecl[ri] = di
			return true
		}
	}
	return false
}

// admits reports whether this declared container permits the running one.
func (c Container) admits(r RunningContainer) bool {
	if c.Name != "" && c.Name != r.Name {
		return false
	}
	if c.Digest.String() != r.Digest {
		return false
	}
	rest, ok := c.Command.matchCommand(r.Argv, r.EnvValues)
	if !ok || !c.Args.matchArgs(rest, r.EnvValues) {
		return false
	}
	return c.Mounts.admits(r.BindMounts, r.BindMountKinds, r.MountsObserved) && c.Env.admits(r.EnvNames, r.EnvObserved)
}

// admits reports whether every bind destination is one this policy names.
func (p MountPolicy) admits(destinations []string, kinds map[string]string, observed bool) bool {
	if p.Policy != PolicyExact {
		return true
	}
	if !observed {
		return false
	}
	if !everyIn(destinations, p.Destinations) {
		return false
	}
	for destination, expected := range p.Kinds {
		if !mountProvenanceSatisfies(kinds[destination], expected) {
			return false
		}
	}
	return true
}

// admits reports whether every environment name is one this policy names.
func (p EnvPolicy) admits(names []string, observed bool) bool {
	if p.Policy != PolicyExact {
		return true
	}
	if !observed {
		return false
	}
	allowed := make(map[string]struct{}, len(p.Names))
	for _, name := range p.Names {
		allowed[name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := allowed[name]; ok {
			continue
		}
		matchedPrefix := false
		for _, prefix := range p.Prefixes {
			if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
				matchedPrefix = true
				break
			}
		}
		if !matchedPrefix {
			return false
		}
	}
	return true
}

func mountProvenanceSatisfies(observed, expected string) bool {
	class := func(value string) string {
		switch value {
		case "private":
			return "private"
		case "pod", "empty-dir", "configmap", "secret", "projected", "downward-api":
			return "pod"
		case "node", "host-path":
			return "node"
		default:
			return ""
		}
	}
	got := class(observed)
	if got == "" {
		return false
	}
	// The legacy empty-dir value did not say whether Medium was Memory. Accept
	// either modern emptyDir provenance for that old expectation only.
	if expected == "empty-dir" {
		return got == "private" || got == "pod"
	}
	want := class(expected)
	return want != "" && got == want
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
