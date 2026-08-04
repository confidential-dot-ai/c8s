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
// with no network. The set is then extended at runtime by the CDS
// allowlist refresh (cds_refresh.go) — the effective allowlist is the
// baked seed UNION every digest CDS has served. See MergePulled and
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
	"strings"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// allowlist holds the parsed, normalised set of permitted digests. The
// zero value is empty; deny everything in that case (load returns an
// error on empty input so the daemon never enters a permissive state
// silently — operators get a clear startup failure instead).
//
// It is read concurrently by per-container decision goroutines
// (Contains) and written by the CDS refresh loop (MergePulled), so the
// digest set is guarded by mu.
type allowlist struct {
	mu sync.RWMutex
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
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.digests[norm]
	return ok
}

// MergePulled adds CDS-pulled digests on top of the existing set and
// returns the number of newly-added (previously-unseen) entries.
// Malformed entries are skipped. It only ever ADDS — a transient CDS
// outage can never shrink enforcement below the baked seed. Thread-safe
// against concurrent Contains.
func (a *allowlist) MergePulled(digests []string) int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	added := 0
	for _, d := range digests {
		norm, err := normalizeDigest(d)
		if err != nil {
			continue
		}
		if _, ok := a.digests[norm]; !ok {
			a.digests[norm] = struct{}{}
			added++
		}
	}
	return added
}

// Size returns the number of accepted entries. Used in startup + refresh
// logs so operators can see the seed loaded and the set growing.
func (a *allowlist) Size() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.digests)
}

// extractDigest returns the container's image digest from its OCI
// annotations, in canonical "sha256:<64hex>" form. Key priority and
// normalisation live in types.DigestFromAnnotations; a miss means "no
// digest available", which the caller denies.
func extractDigest(annotations map[string]string) (string, bool) {
	d, ok := types.DigestFromAnnotations(annotations)
	if !ok {
		return "", false
	}
	return d.String(), true
}

// k8sContainerTypeKeys mirrors kata-agent's K8S_CONTAINER_TYPE_KEYS
// (src/agent/src/confidential_data_hub/image.rs in kata-containers
// 3.30.0): the annotation keys a CRI runtime uses to mark a container's
// type. A value of "sandbox" identifies the pod's sandbox (pause)
// container.
var k8sContainerTypeKeys = []string{
	"io.kubernetes.cri.container-type",  // containerd CRI
	"io.kubernetes.cri-o.ContainerType", // CRI-O
}

// isSandbox reports whether the OCI annotations mark this as the pod's
// sandbox (pause) container. It mirrors kata-agent's own is_sandbox()
// EXACTLY (same keys, same "sandbox" value), and that lockstep is
// load-bearing for safety, not cosmetic. In guest-pull mode — which c8s
// forces (shared_fs=none + experimental_force_guest_pull) — kata-agent's
// get_process() overrides ANY container it deems a sandbox with the
// pause process baked into the dm-verity rootfs (/pause_bundle),
// ignoring whatever image the host requested. So a container the host
// labels "sandbox" runs the measured pause, never a host-chosen image.
// policy-monitor can therefore skip digest enforcement on exactly the
// set kata treats as sandboxes: an adversarial host gains nothing by
// mislabelling a workload as a sandbox, because kata won't run its image
// either way. Identifying sandboxes any LOOSER than kata does would open
// a bypass, so keep these keys in lockstep with the kata version the
// guest is built against.
func isSandbox(annotations map[string]string) bool {
	for _, key := range k8sContainerTypeKeys {
		if annotations[key] == "sandbox" {
			return true
		}
	}
	return false
}

// normalizeDigest takes any of the forms we see in the wild
// (types.NormalizeDigest) and returns the bare 64-hex string — this
// package's allowlist map keys carry no "sha256:" prefix.
func normalizeDigest(s string) (string, error) {
	d, err := types.NormalizeDigest(s)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(d.String(), "sha256:"), nil
}
