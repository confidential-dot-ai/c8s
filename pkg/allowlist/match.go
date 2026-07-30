package allowlist

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

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
	return ok && c.Args.matchArgs(rest)
}

// MatchingWorkloadEntries returns the sorted names of every workload entry
// consistent with all the given running containers: each non-floor container's
// digest AND argv must be admitted by some container the entry declares.
// Shared by CDS (which stamps the match onto issued leaves) and verifiers
// (which recompute it from the attested allowlist), so the two sides cannot
// drift.
//
// Floor containers are excluded before matching: floor digests are admitted
// alone and carry no combination policy, and the platform's injected sidecars
// are floor entries, so a workload entry never has to enumerate them.
//
// Unlike MatchWorkload it does not require every declared main container to be
// running: issuance happens at arbitrary points in the pod lifecycle — during
// init, between mains coming up, after completed inits are reaped — so the
// running set is routinely a strict subset of what the entry declares.
// "Everything running is something this entry declares (digest and argv)" is
// the subset-safe form of the same policy.
//
// More than one name is a real outcome, not an error: two entries can admit
// the same (digest, argv) set — e.g. both carrying an "any" argv policy over
// the same image. Callers that stamp the result MUST carry the whole set
// rather than picking one, because picking one would assert an identity the
// evidence does not establish. Argv discrimination narrows this over the
// digest-only match: entries whose argv policy the running commands do not
// satisfy drop out.
//
// An empty result with non-floor containers present means no entry admits the
// set. A floor-only (or empty) set also returns empty — there is no workload
// entry to name; distinguish the two with HasNonFloor.
func (a *Allowlist) MatchingWorkloadEntries(running []RunningContainer) []string {
	nonFloor := a.nonFloorContainers(running)
	if len(nonFloor) == 0 {
		return nil
	}
	var names []string
	for name, w := range a.Workloads {
		declared := make([]Container, 0, len(w.Containers)+len(w.InitContainers))
		declared = append(declared, w.Containers...)
		declared = append(declared, w.InitContainers...)
		consistent := true
		for _, r := range nonFloor {
			if !admittedBy(declared, r) {
				consistent = false
				break
			}
		}
		if consistent {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// HasNonFloor reports whether any running container is not a floor entry —
// i.e. whether there is anything for MatchingWorkloadEntries to match at all.
func (a *Allowlist) HasNonFloor(running []RunningContainer) bool {
	return len(a.nonFloorContainers(running)) > 0
}

// nonFloorContainers is the subset of running whose digests are not floor
// entries.
// NonFloorContainers returns the containers whose digest is not a floor
// entry — the ones workload-entry matching actually considers. Exported so
// CDS can pre-screen the same subset the matcher will see (e.g. for the
// missing-argv degradation) without duplicating the floor rule.
func (a *Allowlist) NonFloorContainers(running []RunningContainer) []RunningContainer {
	return a.nonFloorContainers(running)
}

func (a *Allowlist) nonFloorContainers(running []RunningContainer) []RunningContainer {
	out := make([]RunningContainer, 0, len(running))
	for _, r := range running {
		if _, isFloor := a.Digests[r.Digest]; isFloor {
			continue
		}
		out = append(out, r)
	}
	return out
}

// WorkloadEntriesDigest is SHA-256 over the canonical encoding of the named
// workload entries: json.Marshal of the name→Workload sub-map (deterministic —
// Go sorts map keys, and the entries themselves are normalized on load). It
// covers everything the entries say, most importantly each container's
// Command/Args argv policy — the part that distinguishes two entries sharing an
// image digest.
//
// A verifier holding the raw allowlist recomputes this from the parsed
// document, so the digest is checkable against the same attested bytes the
// live-allowlist claim covers. Unknown names fail rather than digesting an
// empty entry.
func (a *Allowlist) WorkloadEntriesDigest(names []string) ([]byte, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("allowlist: no workload entry names to digest")
	}
	sub := make(map[string]Workload, len(names))
	for _, n := range names {
		w, ok := a.Workloads[n]
		if !ok {
			return nil, fmt.Errorf("allowlist: workload entry %q not present", n)
		}
		sub[n] = w
	}
	canonical, err := json.Marshal(sub)
	if err != nil {
		return nil, fmt.Errorf("allowlist: marshal workload entries: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}
