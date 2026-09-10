// Package admissionhistory records a sandbox's cumulative container inventory.
package admissionhistory

import (
	"fmt"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// History retains distinct admissions for a sandbox's lifetime. The zero value
// is ready to use; callers must synchronise access.
type History struct {
	byKey      map[string]workloadclaims.SandboxContainer
	unresolved map[string]struct{}
}

// Record adds an admission; only a resolved record for the same ID clears an
// unresolved container. History owns its copy of argv.
func (h *History) Record(id, digest string, argv []string, env ...*allowlist.EnvObservation) {
	if h.byKey == nil {
		h.byKey = map[string]workloadclaims.SandboxContainer{}
		h.unresolved = map[string]struct{}{}
	}
	if digest == "" {
		h.unresolved[id] = struct{}{}
		return
	}
	delete(h.unresolved, id)
	c := workloadclaims.SandboxContainer{Digest: digest, Argv: slices.Clone(argv)}
	if len(env) > 0 {
		c.Env = env[0].Clone()
	}
	h.byKey[c.Key()] = c
}

// Snapshot returns sorted, independent copies of the digest set and admissions.
// An unresolved container makes the entire snapshot unavailable.
func (h History) Snapshot() ([]string, []workloadclaims.SandboxContainer, error) {
	if len(h.unresolved) > 0 {
		return nil, nil, fmt.Errorf("admitted a container with no resolved image digest")
	}
	digests := []string{}
	containers := make([]workloadclaims.SandboxContainer, 0, len(h.byKey))
	for _, c := range h.byKey {
		digests = append(digests, c.Digest)
		c.Argv = slices.Clone(c.Argv)
		c.Env = c.Env.Clone()
		containers = append(containers, c)
	}
	slices.Sort(digests)
	slices.SortFunc(containers, workloadclaims.SandboxContainer.Compare)
	return slices.Compact(digests), containers, nil
}
