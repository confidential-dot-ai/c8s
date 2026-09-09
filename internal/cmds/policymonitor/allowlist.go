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
// Match semantics: the seed is an allowlist.Index built by DigestIndex, which
// admits each entry whatever it runs. The match is exact digest equality. We do
// not try to be clever about image-tag aliases (no registry-side digest
// resolution) — the point of post-attestation enforcement is "the bytes you
// measured are the bytes you ran", and digest equality is the only honest
// definition of that.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// bootstrapAllowlistFile is the on-disk JSON shape. Fields that aren't
// recognised by this parser (e.g. `_comment`) are silently ignored by
// the json package — operators can add inline notes without breaking
// the load.
type bootstrapAllowlistFile struct {
	Sha256Digests []string `json:"sha256_digests"`
}

// loadAllowlist parses the on-disk JSON allowlist and returns the seed index.
// Returns a non-nil error when:
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
//
// The returned index is written once here and only read after that, so
// per-container decision goroutines share it without a lock.
func loadAllowlist(path string) (*allowlist.Index, []error, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read allowlist %s: %w", path, err)
	}

	var file bootstrapAllowlistFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, nil, fmt.Errorf("parse allowlist %s: %w", path, err)
	}

	seed, warnings := allowlist.DigestIndex(file.Sha256Digests)
	if seed.Size() == 0 {
		return nil, warnings, errors.New("allowlist contains no valid digests; refusing to start (bake-time defect)")
	}
	return seed, warnings, nil
}
