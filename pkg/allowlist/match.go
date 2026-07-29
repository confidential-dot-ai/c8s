// Workload-entry matching: which allowlist entries a pod's container-digest
// sets correspond to, and a canonical digest over those entries. Shared by CDS
// (which stamps the match onto issued leaves) and verifiers (which recompute it
// from the attested allowlist), so the two sides cannot drift.

package allowlist

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// MatchingWorkloadEntries returns the sorted names of every workload entry
// whose non-floor init/main digest sets equal the claimed ones. Floor digests
// are excluded from both sides: they are admitted alone and carry no
// combination policy.
//
// More than one name is a real outcome, not an error: the match is over image
// digests only (argv never reaches CDS), so two entries sharing digests and
// differing only in argv policy — the same-image-different-model case — both
// match. Callers that stamp the result MUST carry the whole set rather than
// picking one, because picking one would assert an identity the digests do not
// establish.
//
// An empty result with non-empty claimed sets means no entry matches. Both
// claimed sets reducing to empty (floor-only pod) also returns empty — there is
// no workload entry to name.
func (a *Allowlist) MatchingWorkloadEntries(initDigests, mainDigests []string) []string {
	claimInit := a.nonFloorSet(initDigests)
	claimMain := a.nonFloorSet(mainDigests)
	if len(claimInit) == 0 && len(claimMain) == 0 {
		return nil
	}
	var names []string
	for name, w := range a.Workloads {
		if digestSetsEqual(claimInit, a.nonFloorSet(containerDigestStrings(w.InitContainers))) &&
			digestSetsEqual(claimMain, a.nonFloorSet(containerDigestStrings(w.Containers))) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
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

// nonFloorSet is the canonical digests in ds that are not floor entries.
// Unparseable digests are skipped: the caller has already validated the claimed
// lists, and entry-side digests are normalized on load.
func (a *Allowlist) nonFloorSet(ds []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		parsed, err := types.ParseDigest(d)
		if err != nil {
			continue
		}
		if _, isFloor := a.Digests[parsed.String()]; isFloor {
			continue
		}
		set[parsed.String()] = struct{}{}
	}
	return set
}

func containerDigestStrings(cs []Container) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Digest.String()
	}
	return out
}

func digestSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
