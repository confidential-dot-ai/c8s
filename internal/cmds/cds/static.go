package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// staticSeedPath is the one --allowlist-seed static mode accepts: the bundle
// member the node measured, read from the measurer's output directory.
func staticSeedPath(policyDir string) string {
	return filepath.Join(policyDir, policybundle.MemberStaticAllowlist)
}

// validateStaticConfig refuses every flag combination under which a static
// CDS could admit something the bundle did not seal: an operator key (writes
// to the store), a persistent store (entries surviving a reseed), a
// verifier reached over the network (a control-plane-chosen verdict), a seed
// other than the measured member, or a measurements entry that leaves a
// register unpinned. It returns the one entry /attest enforces.
func validateStaticConfig(cfg config, pinned measurements.ReferenceValues) (measurements.Entry, error) {
	if ratls.NormalizePlatform(cfg.ratlsPlatform) != measurements.TEETDX {
		return measurements.Entry{}, fmt.Errorf("--static-allowlist requires --ratls-platform=tdx: only TDX has the runtime register the policy is measured into")
	}
	if cfg.measurementsConfig == "" {
		return measurements.Entry{}, fmt.Errorf("--static-allowlist requires --measurements-config with the cluster's static entry (MRTD, RTMR[1], RTMR[2], RTMR[3])")
	}
	if cfg.operatorKeys != "" {
		return measurements.Entry{}, fmt.Errorf("--static-allowlist cannot be combined with --operator-keys: the allowlist is sealed at boot and takes no operator writes")
	}
	if cfg.allowlistPersistent {
		return measurements.Entry{}, fmt.Errorf("--static-allowlist cannot be combined with --allowlist-persistent: every start reseeds from the measured bundle so no stored entry can outlive it")
	}
	if want := staticSeedPath(cfg.policyDir); filepath.Clean(cfg.allowlistSeed) != want {
		return measurements.Entry{}, fmt.Errorf("--static-allowlist requires --allowlist-seed=%s (the measured bundle member), got %q", want, cfg.allowlistSeed)
	}
	if !strings.HasPrefix(cfg.attestationApiURL, "unix://") {
		return measurements.Entry{}, fmt.Errorf("--static-allowlist requires a unix:// --attestation-api-url: a verifier reached over the network is one the control plane can substitute")
	}
	entry, err := pinned.StaticEntry()
	if err != nil {
		return measurements.Entry{}, fmt.Errorf("--measurements-config: %w", err)
	}
	return entry, nil
}

// verifyStaticNode is the static start gate: the measurer must have written
// mode=static, the members under the policy dir must index to the digest it
// published, that index must derive the RTMR[3] the static entry pins, and
// this pod's own evidence — verified by the node's local attestation-api —
// must carry exactly the static tuple. The middle link is what ties the seed
// to the register: the policy dir is node-root-writable, so a member and
// digest rewritten together still index consistently, and only the register
// (which nothing after boot can move) says which bundle was measured. It
// returns the bundle so the seed comes from the bytes that were checked.
func verifyStaticNode(ctx context.Context, cfg config, entry measurements.Entry) (policybundle.Bundle, error) {
	state, err := policybundle.ReadDir(cfg.policyDir)
	if err != nil {
		return policybundle.Bundle{}, fmt.Errorf("--static-allowlist: %w", err)
	}
	if state.Mode != policybundle.StaticMode {
		return policybundle.Bundle{}, fmt.Errorf("--static-allowlist: %s reports mode %q, want %s: this node did not boot a policy bundle", filepath.Join(cfg.policyDir, policybundle.ModeFile), state.Mode, policybundle.StaticMode)
	}
	if reg := state.Bundle.RTMR3(); !bytes.Equal(reg[:], entry.RTMRs[3]) {
		return policybundle.Bundle{}, fmt.Errorf("--static-allowlist: members under %s derive RTMR[3] %x, the static entry pins %x: this node's bundle is not the one the cluster was installed with (was a member replaced after boot?)", cfg.policyDir, reg, entry.RTMRs[3])
	}
	if err := verifySelfEvidence(ctx, cfg.attestationApiURL, entry); err != nil {
		return policybundle.Bundle{}, fmt.Errorf("--static-allowlist: this pod's evidence does not match the static entry: %w", err)
	}
	digest := state.Bundle.IndexDigest()
	slog.Info("static allowlist mode: node evidence matches the static entry",
		"policy_dir", cfg.policyDir,
		"index_digest", hex.EncodeToString(digest[:]),
		"rtmr3", hex.EncodeToString(entry.RTMRs[3]))
	return state.Bundle, nil
}

// verifySelfEvidence has the node's attestation-api attest and verify this
// pod and requires the tuple it reports to be the static entry's. The
// register compare happens on the verifier's verdict, not on sysfs: the pod
// cannot read the register, and the same verdict path is what /attest
// applies to every requester.
func verifySelfEvidence(ctx context.Context, attestationAPIURL string, entry measurements.Entry) error {
	ctx, cancel := context.WithTimeout(ctx, attestationclient.OwnTupleTimeout)
	defer cancel()

	own, err := attestationclient.NewClient(attestationAPIURL).OwnTupleEntry(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(own.Digest, entry.Digest) {
		return fmt.Errorf("MRTD %x does not match the static entry's %x", own.Digest, entry.Digest)
	}
	for _, i := range slices.Sorted(maps.Keys(entry.RTMRs)) {
		if !bytes.Equal(own.RTMRs[i], entry.RTMRs[i]) {
			return fmt.Errorf("RTMR[%d] does not match the static entry: this node reports %x, the entry pins %x", i, own.RTMRs[i], entry.RTMRs[i])
		}
	}
	return nil
}

// checkStaticStamp requires the store, seeded from member, to serve a document
// whose canonical digest is SHA-256 of member itself. That digest is what
// every leaf's matched-workload stamp carries and what `c8s verify
// --static-allowlist` holds the stamp to, so a member the store would
// re-serialize differently (a document without "digests":{} is the known
// case: the store always serves an empty map) must stop CDS here rather than
// mint stamps no bundle holder can match.
func checkStaticStamp(store policyStore, member []byte) error {
	snapshot, err := loadPolicySnapshot(store)
	if err != nil {
		return err
	}
	want := sha256.Sum256(member)
	if !bytes.Equal(snapshot.Digest, want[:]) {
		return fmt.Errorf("the seeded store serves policy digest %x but the measured %s digests to %x: the member is not in the form the store serves (it must carry \"digests\":{} and a \"workloads\" object, as `c8s allowlist render --sealed` writes it), so leaf stamps would match no verifier's copy of the bundle", snapshot.Digest, policybundle.MemberStaticAllowlist, want)
	}
	return nil
}
