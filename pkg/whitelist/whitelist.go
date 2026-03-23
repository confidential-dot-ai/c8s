// Package whitelist provides types and file loading for image digest whitelists.
package whitelist

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
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

// ParseJSON parses a whitelist from JSON data.
// Used by both file loading (k3s) and KBS response parsing (AKS).
func ParseJSON(data []byte) (*Whitelist, error) {
	var wl Whitelist
	if err := json.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("decode whitelist: %w", err)
	}

	if len(wl.Digests) == 0 {
		return nil, fmt.Errorf("whitelist has no digests")
	}

	for digest := range wl.Digests {
		if !isValidDigest(digest) {
			return nil, fmt.Errorf("invalid digest format: %q (expected sha256:<64 hex chars>)", digest)
		}
	}

	return &wl, nil
}

// isValidDigest checks that a digest is sha256:<64 hex chars>.
func isValidDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}
