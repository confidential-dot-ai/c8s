//go:build linux

package policymonitor

// Bootstrap allowlist loading and matching.
//
// The on-disk format is:
//
//	{
//	  "_comment": "free-form, ignored by the parser",
//	  "sha256_digests": ["sha256:aaaaaaaa...", "sha256:bbbbbbbb..."]
//	}
//
// The file is baked into the guest's dm-verity rootfs at build time;
// kata-guest-base/scripts/fetch.sh substitutes the c8s container image
// digests into the template before osbuilder materializes the rootfs.
// It is the SEED: read once at boot so the guest can enforce from t=0
// with no network. The CDS allowlist refresh (cds_refresh.go) installs the
// served document beside it as the policy overlay — the effective allowlist
// is the baked seed UNION the latest served document. See
// docs/kata-image-policy.md.
//
// Match semantics:
//
//   - Allowlist entries are normalised to bare 64-hex strings (no
//     "sha256:" prefix, lowercased) at load time.
//   - On lookup, the candidate digest is normalised the same way before
//     comparison. Anything that doesn't normalise to 64 hex chars is
//     treated as "no digest available" and the container is denied.
//   - The match is exact-equality. We do not try to be clever about
//     image-tag aliases (no registry-side digest resolution) — the
//     point of post-attestation enforcement is "the bytes you measured
//     are the bytes you ran", and digest equality is the only honest
//     definition of that.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// allowlist holds the parsed, normalised set of permitted digests. The
// zero value is empty; deny everything in that case (load returns an
// error on empty input so the daemon never enters a permissive state
// silently — operators get a clear startup failure instead).
//
// It is written once by loadAllowlist and only read after that, so
// per-container decision goroutines share it without a lock.
type allowlist struct {
	// digests is the set of bare hex strings (no "sha256:" prefix).
	digests map[string]struct{}
}

// bootstrapAllowlistFile is the on-disk JSON shape. Fields that aren't
// recognised by this parser (e.g. `_comment`) are silently ignored by
// the json package — operators can add inline notes without breaking
// the load.
type bootstrapAllowlistFile struct {
	Sha256Digests []string `json:"sha256_digests"`
}

// loadAllowlist parses the on-disk JSON allowlist and returns a ready-
// to-use *allowlist. Returns a non-nil error when:
//   - the file cannot be opened (most likely cause: IGVM build defect);
//   - the JSON is malformed;
//   - the file contains no entries at all (we refuse to start with an
//     empty allowlist — operators should either populate it or remove
//     the policy-monitor systemd unit from the preset).
//
// Entries that are present but malformed are logged via the returned
// errs slice; the loader does not refuse to start over a single bad
// entry, because the threat model favours "best-effort enforcement
// with some allowlisted images" over "no enforcement because one
// digest had a typo".
func loadAllowlist(path string) (*allowlist, []error, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read allowlist %s: %w", path, err)
	}

	var file bootstrapAllowlistFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, nil, fmt.Errorf("parse allowlist %s: %w", path, err)
	}

	a := &allowlist{digests: make(map[string]struct{}, len(file.Sha256Digests))}
	var warnings []error
	for _, d := range file.Sha256Digests {
		norm, err := normalizeDigest(d)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("skip allowlist entry %q: %w", d, err))
			continue
		}
		a.digests[norm] = struct{}{}
	}

	if len(a.digests) == 0 {
		return nil, warnings, errors.New("allowlist contains no valid digests; refusing to start (bake-time defect)")
	}
	return a, warnings, nil
}

// Contains reports whether digest (in any of the accepted formats) is on
// the allowlist. Returns false on any malformed or empty input — the
// caller treats that as "not allowlisted" and proceeds to kill.
func (a *allowlist) Contains(digest string) bool {
	if a == nil {
		return false
	}
	norm, err := normalizeDigest(digest)
	if err != nil {
		return false
	}
	_, ok := a.digests[norm]
	return ok
}

// Size returns the number of accepted entries, for the startup and refresh
// logs.
func (a *allowlist) Size() int {
	if a == nil {
		return 0
	}
	return len(a.digests)
}

// normalizeDigest takes any of the forms we see in the wild
// (types.NormalizeDigest) and returns the bare 64-hex string — this
// package's allowlist map keys carry no "sha256:" prefix.
func normalizeDigest(s string) (string, error) {
	d, err := types.NormalizeDigest(s)
	return d.Hex(), err
}
