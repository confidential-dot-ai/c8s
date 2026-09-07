// Package credrelease implements the in-guest credential-release service (B4
// of the operator-key design). It issues an operator a short-lived kube client
// certificate, but only to a caller who proves possession of the operator
// private key whose public half was bound into the CVM's launch identity
// (TDX RTMR[3] / SNP HOSTDATA) at launch — giving an external operator
// console-free, non-TOFU admin access with no pre-shared cluster secret and
// no trust in the untrusted host.
package credrelease

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key it read off the opkeydata disk (and hashed into RTMR[3]). The service
// reads this file rather than mounting the ISO itself — mounting fails under
// the unit's systemd hardening, and the initrd is the single, measured reader
// of the disk anyway.
// Var (not const) so tests can point it at a temp file.
var operatorPubkeyPath = "/etc/confai/operator-pubkey"

// rtmr3SysfsPath is the TDX runtime-measurement register the initrd extended
// with the operator key digest before switch_root. Reading it back lets the
// service confirm the on-disk operator pubkey is the one that was measured.
// Var (not const) so tests can point it at a temp file.
var rtmr3SysfsPath = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

// tdxGuestSysfsDir is the tdx_guest sysfs directory OwnLaunchMeasurement reads
// mrtd/rtmr1/rtmr2 from — a plain read of this guest's own measured state, no
// attestation round trip. Var (not const) so tests can point it at a fake
// tree.
var tdxGuestSysfsDir = "/sys/devices/virtual/misc/tdx_guest/measurements"

// readOwnRTMR3 reads the guest's current RTMR[3] from the tdx_guest sysfs.
// Returns the raw 48 bytes.
func readOwnRTMR3() ([]byte, error) {
	return readRegister(rtmr3SysfsPath)
}

// readRegister reads a 48-byte (SHA-384) binary TDX measurement register
// file at path, failing closed on anything but exactly 48 bytes — a short or
// missing read must never be silently zero-padded into a register compare.
func readRegister(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (is this a TDX guest with runtime measurement?)", path, err)
	}
	if len(b) != 48 {
		return nil, fmt.Errorf("%s: got %d bytes, want 48", path, len(b))
	}
	return b, nil
}

// verifyKeyMeasured is the load-bearing anchor check: the operator pubkey file
// is NOT itself measured (only its hash, via RTMR[3]), so before trusting the
// on-disk key the service confirms it is the key that was measured. A host
// that swapped the pubkey file post-boot produces a mismatch here — it cannot
// forge RTMR[3], which is set by the (measured) initrd and sealed by the TD.
//
// With this check, the on-disk pubkey is anchored to RTMR[3], and RTMR[3] is
// what the operator's own attestation pins to their key: both directions bind
// to the same measured key, so neither side trusts the host.
func verifyKeyMeasured(pubkey []byte) error {
	own, err := readOwnRTMR3()
	if err != nil {
		return err
	}
	// The bare operator-key seed — no workload extends — is correct HERE, at
	// service startup, even though remote verifiers compare against the seeded
	// workload chain: the node image runs no workload measurer, so at this
	// moment RTMR[3] must equal the seed exactly. Any extension beyond it means
	// an unexpected measurer ran or the register was tampered with, and the
	// comparison fails closed.
	want := runtimemeasure.ForOperatorKey(pubkey)
	// Not secret (a public-key hash) — plain compare is fine.
	if !bytes.Equal(own, want[:]) {
		return fmt.Errorf(
			"operator pubkey does not match the measured RTMR[3]: got %s, key implies %s (was the pubkey file substituted after boot?)",
			hex.EncodeToString(own), hex.EncodeToString(want[:]))
	}
	return nil
}

// ReadOperatorPubkey reads the operator public key the initrd staged from the
// opkeydata disk. The bytes are exactly what the initrd hashed into RTMR[3],
// so verifyKeyMeasured can re-derive the same digest. Absence means the VM was
// launched without an operator key (no opkeydata disk) — errors.Is(err,
// fs.ErrNotExist) distinguishes that from every other read failure; os.
// ReadFile's *PathError wraps the underlying fs error, and %w below preserves
// that chain, so callers can rely on errors.Is rather than string matching.
func ReadOperatorPubkey() ([]byte, error) {
	pub, err := os.ReadFile(operatorPubkeyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w — was the VM launched with an operator key?", operatorPubkeyPath, err)
	}
	if len(pub) == 0 {
		return nil, fmt.Errorf("%s is empty", operatorPubkeyPath)
	}
	return pub, nil
}

// selfReportTimeout bounds the SNP self-attestation round trip against the
// local attestation-api; on expiry the service fails start and systemd
// retries, same as a failed RTMR read on TDX.
const selfReportTimeout = 15 * time.Second

// selfReport attests this guest against the local attestation-api and
// returns the verified claims — reading a field off an unverified self-report
// would take the anchor from an unauthenticated value. Mirrors
// policymonitor's verifiedSelfHostData, with a random anchor: nothing here
// needs the zero-anchor convention, and a fresh nonce makes the self-report
// non-replayable for free.
//
// Called once per SNP operator boot and shared by both binding checks that
// need it (the HOSTDATA anchor for the operator key, and this guest's own
// launch digest for OwnLaunchMeasurement) so an SNP boot attests itself only
// once, not once per caller.
func selfReport(ctx context.Context, attestationAPIURL string) (types.Claims, error) {
	ctx, cancel := context.WithTimeout(ctx, selfReportTimeout)
	defer cancel()

	// The attester is asked for the 48-byte prefix and zero-extends it into
	// the 64-byte REPORTDATA the verifier must find.
	var reportData [64]byte
	if _, err := rand.Read(reportData[:sha512.Size384]); err != nil {
		return types.Claims{}, fmt.Errorf("self-report nonce: %w", err)
	}
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, attestationAPIURL, reportData[:sha512.Size384])
	if err != nil {
		return types.Claims{}, fmt.Errorf("attest self: %w", err)
	}
	verified, err := attestationclient.NewClient(attestationAPIURL).VerifyEvidence(ctx,
		types.AttestationEvidence(resp), attestationclient.EvidencePolicy{ExpectedReportData: reportData})
	if err != nil {
		return types.Claims{}, fmt.Errorf("verify self-report: %w", err)
	}
	return verified.Result.Claims, nil
}

// verifyKeyLaunchBound is the SNP analog of verifyKeyMeasured: before trusting
// the on-disk key the service confirms sha256(file bytes) equals the HOSTDATA
// the launcher committed at launch. HOSTDATA is immutable post-launch and
// carried in every report, so a host that swapped the pubkey file post-boot
// produces a mismatch here — it cannot alter HOSTDATA any more than it can
// rewind RTMR[3]. A VM launched without an operator key carries all-zero
// HOSTDATA, which no SHA-256 output equals, so that fails closed too.
//
// claims comes from one selfReport call the caller makes; see
// LoadMeasuredOperatorKey.
func verifyKeyLaunchBound(claims types.Claims, pubkey []byte) error {
	hostData := []byte(claims.InitData)
	// A TDX report leaking into this arm carries a 48-byte MRCONFIGID here
	// and is refused by length, not silently truncated.
	if len(hostData) != runtimemeasure.HostDataSize {
		return fmt.Errorf("HOSTDATA claim is %d bytes, want %d", len(hostData), runtimemeasure.HostDataSize)
	}
	want := runtimemeasure.HostDataForOperatorKey(pubkey)
	// Not secret (a public-key hash) — plain compare is fine.
	if !bytes.Equal(hostData, want[:]) {
		return fmt.Errorf(
			"operator pubkey does not match the launch-committed HOSTDATA: got %s, key implies %s (was the pubkey file substituted after boot, or the VM launched for a different key?)",
			hex.EncodeToString(hostData), hex.EncodeToString(want[:]))
	}
	return nil
}

// LoadMeasuredOperatorKey reads the operator pubkey the initrd staged off the
// opkeydata disk and verifies it against the platform's launch binding: the
// TDX RTMR[3] the initrd extended, or the SNP HOSTDATA the launcher committed.
// The returned bytes are safe to trust as the authorized operator key. Called
// once at service start; both bindings are fixed for the life of the guest.
// platform is the ratls-normalized platform ("tdx" or "sev-snp").
//
// On SNP this makes its own selfReport call. A caller that ALSO needs this
// guest's own launch measurement on the same boot (launchvalues.Render does,
// on an SNP operator boot with a fragment) should call
// LoadMeasuredOperatorKeyAndOwnMeasurement instead, so the guest self-attests
// once rather than once per check.
func LoadMeasuredOperatorKey(ctx context.Context, platform, attestationAPIURL string) ([]byte, error) {
	pub, err := ReadOperatorPubkey()
	if err != nil {
		return nil, err
	}
	switch platform {
	case "tdx":
		err = verifyKeyMeasured(pub)
	case "sev-snp":
		var claims types.Claims
		claims, err = selfReport(ctx, attestationAPIURL)
		if err == nil {
			err = verifyKeyLaunchBound(claims, pub)
		}
	default:
		// Fail closed: an unknown platform has no binding to check.
		err = fmt.Errorf("no operator-key binding check for platform %q", platform)
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// OwnLaunchMeasurement returns this guest's own launch measurement and (TDX
// only) its runtime measurement register pins — the values c8s-chart-values
// needs to pin cds.measurements/rtmrs and ratlsMesh.measurements/rtmrs to the
// exact image that is running. platform is the ratls-normalized platform
// ("tdx" or "sev-snp").
//
// TDX reads mrtd/rtmr1/rtmr2 straight from the tdx_guest sysfs — a plain
// read, no attestation round trip; the kernel TSM node is this guest's own
// measured state, not a claim a peer could forge. SNP has no such sysfs: its
// launch measurement is only visible in an attestation report, so this reads
// it off one verified selfReport call. A caller that also needs the operator
// key on the same SNP boot should use LoadMeasuredOperatorKeyAndOwnMeasurement
// instead of calling this and LoadMeasuredOperatorKey separately, to avoid
// attesting twice. RTMRs are TDX-only; rtmrs is nil on SNP.
func OwnLaunchMeasurement(ctx context.Context, platform, attestationAPIURL string) (measurement []byte, rtmrs map[int][]byte, err error) {
	switch platform {
	case "tdx":
		mrtd, err := readRegister(filepath.Join(tdxGuestSysfsDir, "mrtd:sha384"))
		if err != nil {
			return nil, nil, err
		}
		rtmr1, err := readRegister(filepath.Join(tdxGuestSysfsDir, "rtmr1:sha384"))
		if err != nil {
			return nil, nil, err
		}
		rtmr2, err := readRegister(filepath.Join(tdxGuestSysfsDir, "rtmr2:sha384"))
		if err != nil {
			return nil, nil, err
		}
		return mrtd, map[int][]byte{1: rtmr1, 2: rtmr2}, nil
	case "sev-snp":
		claims, err := selfReport(ctx, attestationAPIURL)
		if err != nil {
			return nil, nil, err
		}
		return launchDigestFromClaims(claims)
	default:
		return nil, nil, fmt.Errorf("no launch-measurement read for platform %q", platform)
	}
}

// LoadMeasuredOperatorKeyAndOwnMeasurement does what LoadMeasuredOperatorKey
// and OwnLaunchMeasurement do together, but on SNP shares one selfReport call
// between the HOSTDATA check and the launch-digest read instead of attesting
// twice. On TDX the two checks read disjoint sysfs state (RTMR[3] vs
// mrtd/rtmr1/rtmr2) and there is nothing to share, so this is equivalent to
// calling both functions in sequence.
//
// The own measurement is always resolved, operator key present or not — a
// non-operator boot (no opkeydata pubkey, ReadOperatorPubkey's
// errors.Is(err, fs.ErrNotExist)) still needs it for cds/ratlsMesh
// measurements, so pub/pubErr come back alongside measurement/rtmrs rather
// than short-circuiting the whole call. The caller (launchvalues.Render)
// distinguishes "no key staged" from every other pubErr via errors.Is.
//
// This is the entry point launchvalues.Render uses; LoadMeasuredOperatorKey
// and OwnLaunchMeasurement remain exported for callers (tests, other
// services) that only need one half.
func LoadMeasuredOperatorKeyAndOwnMeasurement(ctx context.Context, platform, attestationAPIURL string) (pub []byte, pubErr error, measurement []byte, rtmrs map[int][]byte, err error) {
	if platform != "sev-snp" {
		pub, pubErr = LoadMeasuredOperatorKey(ctx, platform, attestationAPIURL)
		measurement, rtmrs, err = OwnLaunchMeasurement(ctx, platform, attestationAPIURL)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return pub, pubErr, measurement, rtmrs, nil
	}

	pub, pubErr = ReadOperatorPubkey()
	claims, err := selfReport(ctx, attestationAPIURL)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if pubErr == nil {
		if verr := verifyKeyLaunchBound(claims, pub); verr != nil {
			pub, pubErr = nil, verr
		}
	}
	measurement, rtmrs, err = launchDigestFromClaims(claims)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pub, pubErr, measurement, rtmrs, nil
}

// launchDigestFromClaims decodes claims.LaunchDigest (hex) into raw bytes,
// failing closed on anything but exactly SNPMeasurementSize (48) bytes.
func launchDigestFromClaims(claims types.Claims) ([]byte, map[int][]byte, error) {
	digest, err := hex.DecodeString(claims.LaunchDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("launch_digest claim is not hex: %w", err)
	}
	if len(digest) != ratls.SNPMeasurementSize {
		return nil, nil, fmt.Errorf("launch_digest claim is %d bytes, want %d", len(digest), ratls.SNPMeasurementSize)
	}
	return digest, nil, nil
}
