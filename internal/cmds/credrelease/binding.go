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
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
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

// readOwnRTMR3 reads the guest's current RTMR[3] from the tdx_guest sysfs.
// Returns the raw 48 bytes.
func readOwnRTMR3() ([]byte, error) {
	b, err := os.ReadFile(rtmr3SysfsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (is this a TDX guest with runtime measurement?)", rtmr3SysfsPath, err)
	}
	if len(b) != 48 {
		return nil, fmt.Errorf("%s: got %d bytes, want 48", rtmr3SysfsPath, len(b))
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

// readOperatorPubkey reads the operator public key the initrd staged from the
// opkeydata disk. The bytes are exactly what the initrd hashed into RTMR[3],
// so verifyKeyMeasured can re-derive the same digest. Absence means the VM was
// launched without an operator key (no opkeydata disk).
func readOperatorPubkey() ([]byte, error) {
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

// verifiedSelfHostData returns this guest's HOSTDATA as the attestation-api
// reports it, from the claims of a report that api verified — reading it off
// an unverified self-report would take the anchor from an unauthenticated
// field. Mirrors policymonitor's verifiedSelfHostData, with a random anchor:
// nothing here needs the zero-anchor convention, and a fresh nonce makes the
// self-report non-replayable for free.
func verifiedSelfHostData(ctx context.Context, attestationAPIURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, selfReportTimeout)
	defer cancel()

	// The attester is asked for the 48-byte prefix and zero-extends it into
	// the 64-byte REPORTDATA the verifier must find.
	var reportData [64]byte
	if _, err := rand.Read(reportData[:sha512.Size384]); err != nil {
		return nil, fmt.Errorf("self-report nonce: %w", err)
	}
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, attestationAPIURL, reportData[:sha512.Size384])
	if err != nil {
		return nil, fmt.Errorf("attest self: %w", err)
	}
	verified, err := attestationclient.NewClient(attestationAPIURL).VerifyEvidence(ctx,
		types.AttestationEvidence(resp), attestationclient.EvidencePolicy{ExpectedReportData: reportData})
	if err != nil {
		return nil, fmt.Errorf("verify self-report: %w", err)
	}

	hostData := []byte(verified.Result.Claims.InitData)
	// A TDX report leaking into this arm carries a 48-byte MRCONFIGID here
	// and is refused by length, not silently truncated.
	if len(hostData) != runtimemeasure.HostDataSize {
		return nil, fmt.Errorf("HOSTDATA claim is %d bytes, want %d", len(hostData), runtimemeasure.HostDataSize)
	}
	return hostData, nil
}

// verifyKeyLaunchBound is the SNP analog of verifyKeyMeasured: before trusting
// the on-disk key the service confirms sha256(file bytes) equals the HOSTDATA
// the launcher committed at launch. HOSTDATA is immutable post-launch and
// carried in every report, so a host that swapped the pubkey file post-boot
// produces a mismatch here — it cannot alter HOSTDATA any more than it can
// rewind RTMR[3]. A VM launched without an operator key carries all-zero
// HOSTDATA, which no SHA-256 output equals, so that fails closed too.
func verifyKeyLaunchBound(ctx context.Context, attestationAPIURL string, pubkey []byte) error {
	hostData, err := verifiedSelfHostData(ctx, attestationAPIURL)
	if err != nil {
		return err
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
func LoadMeasuredOperatorKey(ctx context.Context, platform, attestationAPIURL string) ([]byte, error) {
	pub, err := readOperatorPubkey()
	if err != nil {
		return nil, err
	}
	switch platform {
	case "tdx":
		err = verifyKeyMeasured(pub)
	case "sev-snp":
		err = verifyKeyLaunchBound(ctx, attestationAPIURL, pub)
	default:
		// Fail closed: an unknown platform has no binding to check.
		err = fmt.Errorf("no operator-key binding check for platform %q", platform)
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
}
