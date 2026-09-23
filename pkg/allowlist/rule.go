package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// Rule is one container policy inside one workload entry: the smallest unit of
// permission a policy update can remove.
//
// It carries the entry's secrets grant because the grant is released to every
// container in the pod, so narrowing it removes each of that entry's running
// instances' permissions even though no container policy changed.
type Rule struct {
	Workload  string         `json:"workload"`
	Role      string         `json:"role"`
	Container Container      `json:"container"`
	Secrets   *SecretsPolicy `json:"secrets,omitempty"`
}

// RuleKey is the immutable name of a rule: sha256 over its JSON, in the same
// canonical form as the document itself (fixed field order, map keys sorted by
// encoding/json). Any narrowing — argv, mounts, environment, secrets — changes
// the key, which is what lets a removed permission be named without shipping
// the old policy document.
func RuleKey(r Rule) string {
	data, err := json.Marshal(r)
	if err != nil {
		// A Rule holds only strings, slices and maps of strings, none of which
		// encoding/json can fail on.
		panic(fmt.Sprintf("allowlist: marshal rule: %v", err))
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Rules enumerates every rule in a normalized allowlist, deduplicated and
// ordered by key so two implementations list the same set in the same order. A
// nil allowlist has no rules.
func Rules(a *Allowlist) []Rule {
	if a == nil {
		return nil
	}
	byKey := map[string]Rule{}
	for name, w := range a.Workloads {
		for _, list := range []struct {
			role       string
			containers []Container
		}{{RoleInit, w.InitContainers}, {RoleMain, w.Containers}} {
			for _, c := range list.containers {
				r := Rule{Workload: name, Role: list.role, Container: c, Secrets: w.Secrets}
				byKey[RuleKey(r)] = r
			}
		}
	}
	out := make([]Rule, 0, len(byKey))
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		out = append(out, byKey[key])
	}
	return out
}

// Removed returns the rules of old that updated no longer contains, ordered by
// key. Comparison is by key alone, so a narrowing that keeps the image digest —
// dropping a mount, pinning an environment value, removing a secret path —
// counts as a removal, and an instance admitted under the old rule keeps
// permissions the new policy does not grant.
func Removed(old, updated *Allowlist) []Rule {
	kept := map[string]struct{}{}
	for _, r := range Rules(updated) {
		kept[RuleKey(r)] = struct{}{}
	}
	var out []Rule
	for _, r := range Rules(old) {
		if _, ok := kept[RuleKey(r)]; !ok {
			out = append(out, r)
		}
	}
	return out
}
