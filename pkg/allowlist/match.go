package allowlist

import (
	"fmt"
	"slices"
	"strings"
)

// RunningContainer holds the launch characteristics observed by an enforcer.
// Missing Env is unavailable evidence and fails exact/deny policies.
//
// Mounts and BindMounts are the same bind-mount observation at two resolutions:
// BindMounts is destinations alone, Mounts also says who staged each source. An
// enforcer fills whichever it can produce, and Mounts wins when both are set.
// The NRI plugin recognises the node's own staging paths, so it fills Mounts.
type RunningContainer struct {
	Digest     string
	Argv       []string
	BindMounts []string
	Mounts     []ObservedMount
	Env        *EnvObservation
}

// ObservedMount is one bind mount an enforcer can attribute: where it lands and
// who staged the bytes behind it. Source is diagnostic — it is what the
// enforcer classified, and what a deny log has to name for a reviewer to act on
// it — never a value policy matches against.
type ObservedMount struct {
	Destination string
	Source      string
	Class       MountClass
}

// MountClass says who chose the bytes behind a bind mount, which is what
// decides whether it can carry code into a container the allowlist admitted.
type MountClass string

const (
	// MountPlatform is a mount the node makes for every pod whatever its spec
	// says: /etc/hosts, /etc/hostname, /etc/resolv.conf, /dev/termination-log,
	// /dev/shm and the serviceaccount projection. No entry lists it.
	MountPlatform MountClass = "platform"
	// MountEmptyDir is an emptyDir of either medium. The operator picks the
	// destination but never the bytes, so a listed destination is the whole
	// check.
	MountEmptyDir MountClass = "emptyDir"
	// MountData is operator-supplied content: configMap, secret, projected, PVC,
	// CSI, local volume, or a subPath of one.
	MountData MountClass = "data"
	// MountHost is the node's own filesystem reaching into the container — a
	// hostPath volume, or any source the enforcer could not attribute. Nothing
	// but a node-TCB floor rule admits one.
	MountHost MountClass = "host"
)

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
	return slices.ContainsFunc(running, func(r RunningContainer) bool {
		return c.admits(r)
	})
}

// admits reports whether this declared container permits the running one.
func (c Container) admits(r RunningContainer) bool {
	if c.Digest.String() != r.Digest {
		return false
	}
	if !c.admitsProcess(r) {
		return false
	}
	return c.Mounts.admits(r) && c.Env.matches(r)
}

func (c Container) admitsProcess(r RunningContainer) bool {
	if c.Digest.String() != r.Digest {
		return false
	}
	rest, ok := c.Command.matchCommand(r.Argv)
	return ok && c.Args.matchArgs(rest)
}

// admits reports whether the container's bind mounts satisfy this policy.
//
// A sandboxed policy meets a classified observation with the node-as-CVM rule
// (admitsMount). Everything else — a non-sandboxed exact policy, or an enforcer
// that reports destinations without saying who staged them — is plain
// containment, which is what the field meant before Sandboxed existed.
func (p MountPolicy) admits(r RunningContainer) bool {
	if p.Policy != PolicyExact {
		return true
	}
	if !p.Sandboxed || r.Mounts == nil {
		return everyIn(observedDestinations(r), p.Destinations)
	}
	for _, m := range r.Mounts {
		if !p.admitsMount(m) {
			return false
		}
	}
	return true
}

// admitsMount applies the sandboxed-workload rule to one classified mount.
// Unknown classes fall to the default and are refused: an enforcer that grew a
// class this policy has never heard of is reporting something nothing reviewed.
func (p MountPolicy) admitsMount(m ObservedMount) bool {
	switch m.Class {
	case MountPlatform:
		return true
	case MountEmptyDir:
		return slices.Contains(p.Destinations, m.Destination)
	case MountData:
		return slices.Contains(p.Destinations, m.Destination) &&
			strings.HasPrefix(m.Destination, DataMountPrefix) &&
			p.Reviews[m.Destination] != ""
	default:
		return false
	}
}

// observedDestinations is the destination list the containment check reads,
// from whichever resolution the enforcer filled.
func observedDestinations(r RunningContainer) []string {
	if r.Mounts == nil {
		return r.BindMounts
	}
	out := make([]string, 0, len(r.Mounts))
	for _, m := range r.Mounts {
		out = append(out, m.Destination)
	}
	return out
}

func (p EnvPolicy) matches(r RunningContainer) bool {
	return p.admitsObservation(r.Env)
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
