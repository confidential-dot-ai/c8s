package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Digest is a validated container image digest in the format "sha256:<64 hex chars>".
// Use ParseDigest to construct one; the zero value is not valid.
type Digest struct {
	value string
}

// ParseDigest validates and returns a Digest from the given string. Hex is
// canonicalized to lowercase: a digest is compared by exact string match, and
// containerd emits lowercase, so a valid uppercase entry (e.g. "sha256:ABCD…")
// must not miss the lowercase resolved digest at lookup time.
func ParseDigest(s string) (Digest, error) {
	hex, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return Digest{}, fmt.Errorf("invalid digest: expected sha256:<64 hex chars>")
	}
	if len(hex) != 64 {
		return Digest{}, fmt.Errorf("invalid digest: expected sha256:<64 hex chars>")
	}
	for _, b := range []byte(hex) {
		if !isHexDigit(b) {
			return Digest{}, fmt.Errorf("invalid digest: expected sha256:<64 hex chars>")
		}
	}
	return Digest{value: "sha256:" + strings.ToLower(hex)}, nil
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// NormalizeDigest parses the digest forms seen in the wild — CRI annotations,
// image refs, containerd status output — into a validated Digest. Recognised
// inputs:
//
//   - "sha256:<64hex>" (any case, e.g. "SHA256:" from upstream tooling)
//   - "<anything>@sha256:<64hex>" — an image ref pulled by digest
//   - "<64hex>" — a bare digest with no algorithm prefix
//
// Anything else returns an error; callers treat that as "no digest".
func NormalizeDigest(s string) (Digest, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(s, "sha256:")
	return ParseDigest("sha256:" + s)
}

// digestAnnotationKeys are the OCI annotation keys that may carry a
// container's image digest, in priority order:
//
//   - "io.kubernetes.cri.image-name" — the canonical key set by
//     containerd's CRI plugin (containerd v1.7.21
//     pkg/cri/annotations/annotations.go:78). Format is usually
//     "<registry>/<image>@sha256:<hex>" when the image was pulled by
//     digest; for tag-only pulls the digest may be absent here and
//     present on the next key.
//   - "io.kubernetes.cri.image-id" — set by some CRI implementations
//     when the image-name only carries the tag; usually a bare
//     "sha256:<hex>".
//   - "org.opencontainers.image.ref.name" — image-spec standard, set
//     by some buildkit-produced images that carry their own digest as
//     an annotation.
var digestAnnotationKeys = []string{
	"io.kubernetes.cri.image-name",
	"io.kubernetes.cri.image-id",
	"org.opencontainers.image.ref.name",
}

// DigestFromAnnotations tries every annotation key that may carry a digest,
// in priority order, returning the first that normalizes to a valid digest.
// If none do, ok is false; enforcers treat that as "no digest available",
// which is denied.
func DigestFromAnnotations(annotations map[string]string) (Digest, bool) {
	for _, key := range digestAnnotationKeys {
		v := annotations[key]
		if v == "" {
			continue
		}
		if d, err := NormalizeDigest(v); err == nil {
			return d, true
		}
	}
	return Digest{}, false
}

// String returns the full digest string.
func (d Digest) String() string {
	return d.value
}

// MarshalText implements encoding.TextMarshaler, enabling Digest as a JSON map key.
func (d Digest) MarshalText() ([]byte, error) {
	return []byte(d.value), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, enabling Digest as a JSON map key.
func (d *Digest) UnmarshalText(data []byte) error {
	parsed, err := ParseDigest(string(data))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Digest) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.value)
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (d *Digest) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseDigest(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
