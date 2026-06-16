// Package whitelist provides types and file loading for image digest whitelists.
package whitelist

import (
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Whitelist represents an image digest whitelist.
// Digests is a map of sha256 digest -> image reference (e.g. "sha256:abc..." -> "docker.io/istio/pilot:1.24.6-distroless").
type Whitelist struct {
	Version string            `json:"version"`
	Digests map[string]string `json:"digests"`
}

// Contains checks if a digest is in the whitelist.
func (w *Whitelist) Contains(digest string) bool {
	_, ok := w.Digests[digest]
	return ok
}

// ParseJSON parses a whitelist from JSON data. An empty Digests map is
// allowed — callers decide whether emptiness is operationally acceptable.
func ParseJSON(data []byte) (*Whitelist, error) {
	var wl Whitelist
	if err := json.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("decode whitelist: %w", err)
	}
	for digest := range wl.Digests {
		if _, err := types.ParseDigest(digest); err != nil {
			return nil, fmt.Errorf("invalid digest format: %q (expected sha256:<64 hex chars>)", digest)
		}
	}
	return &wl, nil
}
