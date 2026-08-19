package nriimagepolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// exemptSnapshot admits a container in an exempt namespace when its image
// digest matches one captured running in that same namespace. The name selects
// what to capture; the resolved digest is what admits — see
// docs/getcert-workload-binding.md, Corner 8.
//
// The set is captured once, when the plugin first connects to a containerd that
// already requires it (Synchronize sees the platform pods that came up before
// the required_plugins gate), and then frozen. The installer deletes the file
// whenever it rewrites the boot config, so a chart install or upgrade is the
// only event that recaptures. A plain restart or node reboot loads the frozen
// file, and load must win there: on a reboot containerd gates every container
// on this plugin, so Synchronize sees an empty node and a recapture would
// freeze nothing.
type exemptSnapshot struct {
	// Namespaces is the exempt set this was captured for. Diagnostic only —
	// regeneration is keyed off the installer deleting the file, not off this.
	Namespaces []string `json:"namespaces"`
	// Digests maps an exempt namespace to the image digests captured under it.
	Digests map[string][]string `json:"digests"`

	index map[string]map[string]struct{} // namespace -> digest set, for lookup
}

// newExemptSnapshot returns an empty snapshot ready to accumulate captures for
// the given exempt namespaces.
func newExemptSnapshot(namespaces []string) *exemptSnapshot {
	return &exemptSnapshot{
		Namespaces: slices.Clone(namespaces),
		Digests:    map[string][]string{},
		index:      map[string]map[string]struct{}{},
	}
}

// add records a captured (namespace, digest). A blank digest is dropped: an
// unresolved image cannot be an admission key.
func (s *exemptSnapshot) add(namespace, digest string) {
	if digest == "" {
		return
	}
	set := s.index[namespace]
	if set == nil {
		set = map[string]struct{}{}
		s.index[namespace] = set
	}
	if _, ok := set[digest]; ok {
		return
	}
	set[digest] = struct{}{}
	s.Digests[namespace] = append(s.Digests[namespace], digest)
	slices.Sort(s.Digests[namespace])
}

// admits reports whether digest was captured running in namespace.
func (s *exemptSnapshot) admits(namespace, digest string) bool {
	if s == nil || digest == "" {
		return false
	}
	_, ok := s.index[namespace][digest]
	return ok
}

// empty reports whether the snapshot captured no digest in any namespace.
func (s *exemptSnapshot) empty() bool {
	return s == nil || len(s.index) == 0
}

// count is the total number of captured digests across all namespaces.
func (s *exemptSnapshot) count() int {
	n := 0
	for _, set := range s.index {
		n += len(set)
	}
	return n
}

// buildIndex populates the lookup index from the decoded Digests map.
func (s *exemptSnapshot) buildIndex() {
	s.index = make(map[string]map[string]struct{}, len(s.Digests))
	for ns, digests := range s.Digests {
		set := make(map[string]struct{}, len(digests))
		for _, d := range digests {
			set[d] = struct{}{}
		}
		s.index[ns] = set
	}
}

// loadExemptSnapshot reads a persisted snapshot. It returns (nil, nil) when the
// file is absent — the caller then captures. A present-but-unreadable file is
// an error: on a host lane the file is host-controlled, so a corrupt snapshot
// is treated as a fault to surface, not silently recaptured.
func loadExemptSnapshot(path string) (*exemptSnapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s exemptSnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse exempt snapshot %q: %w", path, err)
	}
	s.buildIndex()
	return &s, nil
}

// persist writes the snapshot atomically (tmp + rename) so a crash mid-write
// cannot leave a truncated file the next start would load.
func (s *exemptSnapshot) persist(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
