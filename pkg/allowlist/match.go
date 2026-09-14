package allowlist

import (
	"fmt"
	"slices"
)

// RunningContainer holds the launch characteristics observed by an enforcer.
// Missing Env is unavailable evidence and fails exact/deny policies.
//
// Mounts is the node's classified bind-mount observation. Nil means unavailable
// evidence; a non-nil empty slice means no bind mounts were present.
type RunningContainer struct {
	Digest string
	Argv   []string
	Mounts []ObservedMount
	Env    *EnvObservation
}

// ObservedMount is one bind mount an enforcer can attribute: where it lands,
// who staged it, and the backing storage. Source is node-local diagnostic
// detail and is deliberately omitted from the inventory wire format.
type ObservedMount struct {
	Destination string       `json:"destination"`
	Source      string       `json:"-"`
	Class       MountClass   `json:"class"`
	Storage     MountStorage `json:"storage"`
}

type MountStorage string

const (
	MountMemory    MountStorage = "memory"
	MountEncrypted MountStorage = "encrypted"
	MountUnknown   MountStorage = "unknown"
)

// MountClass says who chose the bytes behind a bind mount, which is what
// decides whether it can carry code into a container the allowlist admitted.
type MountClass string

const (
	// MountPlatform is a mount the node makes for every pod whatever its spec
	// says: /etc/hosts, /etc/hostname, /etc/resolv.conf, /dev/termination-log,
	// /dev/shm and the serviceaccount projection. No entry lists it.
	MountPlatform MountClass = "platform"
	// MountEmptyDir is a kubelet emptyDir. Its destination and backing storage
	// are checked separately; a disk-backed emptyDir is not trusted by name.
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
// Exact policies require the node's classified observation and the complete
// listed set. A destination-only view cannot distinguish an emptyDir from a
// hostPath at the same destination.
func (p MountPolicy) admits(r RunningContainer) bool {
	if p.Policy == PolicyAny {
		return true
	}
	if r.Mounts == nil {
		return false
	}
	if p.Policy == PolicyDeny || p.Policy == "" {
		return r.Mounts != nil && !slices.ContainsFunc(r.Mounts, func(m ObservedMount) bool { return m.Class != MountPlatform })
	}
	if p.Policy != PolicyExact {
		return false
	}
	seen := make(map[string]bool, len(p.Destinations))
	for _, m := range r.Mounts {
		if !p.admitsMount(m) {
			return false
		}
		if m.Class == MountPlatform {
			if slices.Contains(p.Destinations, m.Destination) {
				seen[m.Destination] = true
			}
			continue
		}
		if seen[m.Destination] {
			return false
		}
		seen[m.Destination] = true
	}
	return len(seen) == len(p.Destinations)
}

// admitsMount applies the node-CVM rule to one classified mount.
// Unknown classes fall to the default and are refused: an enforcer that grew a
// class this policy has never heard of is reporting something nothing reviewed.
func (p MountPolicy) admitsMount(m ObservedMount) bool {
	switch m.Class {
	case MountPlatform:
		return true
	case MountEmptyDir:
		return slices.Contains(p.Destinations, m.Destination) && p.Reviews[m.Destination] == "" && secureMountStorage(m.Storage)
	case MountData:
		return slices.Contains(p.Destinations, m.Destination) && p.Reviews[m.Destination] != "" && secureMountStorage(m.Storage)
	default:
		return false
	}
}

func secureMountStorage(storage MountStorage) bool {
	return storage == MountMemory || storage == MountEncrypted
}

func (p EnvPolicy) matches(r RunningContainer) bool {
	return p.admitsObservation(r.Env)
}
