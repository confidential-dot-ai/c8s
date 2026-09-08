package attestationclient

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Sentinel errors for the enforced verification paths, matchable via
// [errors.Is]. Transport and API failures keep their existing typed errors
// ([RequestError], [APIError], [UnexpectedError]).
var (
	// ErrSignatureInvalid: the attestation-api reported the hardware
	// signature chain does not verify.
	ErrSignatureInvalid = errors.New("attestationclient: attestation signature invalid")

	// ErrReportDataMismatch: the evidence does not bind the expected
	// REPORTDATA (absent or false report_data_match verdict).
	ErrReportDataMismatch = errors.New("attestationclient: REPORTDATA mismatch in attestation evidence")

	// ErrMeasurementNotAllowed: the verified launch measurement is absent or
	// does not match any of the caller's reference values while some are pinned.
	ErrMeasurementNotAllowed = errors.New("attestationclient: launch measurement not allowed")

	// ErrInvalidLaunchDigest: the /verify response carried a launch digest
	// that is not hex or not measurement-sized — a malformed result, distinct
	// from a policy miss.
	ErrInvalidLaunchDigest = errors.New("attestationclient: launch digest malformed")

	// ErrRTMRNotAllowed: a pinned TDX runtime measurement register is absent,
	// malformed, or does not match the value the policy pins.
	ErrRTMRNotAllowed = errors.New("attestationclient: RTMR not allowed")

	// ErrUnsupportedPlatform: [Client.VerifyEvidence] has no verification
	// rules for the envelope's platform and fails closed.
	ErrUnsupportedPlatform = errors.New("attestationclient: unsupported platform for evidence verification")
)

// launchMeasurementSize is the size of both an SEV-SNP LAUNCH_DIGEST and an
// Intel TDX MRTD (SHA-384).
const launchMeasurementSize = 48

// VerifyEnforced posts req to /verify and fails closed on the verdict
// ([EnforceVerdict]). Every caller that trusts a /verify response must gate on
// the verdict fields; doing it here keeps the nil-tolerant fail-open bug out
// of call sites.
func (c Client) VerifyEnforced(ctx context.Context, req types.VerifyRequest) (types.VerifyResponse, error) {
	resp, err := c.Verify(ctx, req)
	if err != nil {
		return types.VerifyResponse{}, err
	}
	if err := EnforceVerdict(req, resp); err != nil {
		return types.VerifyResponse{}, err
	}
	return resp, nil
}

// EnforceVerdict fails closed on a /verify response's verdict: the hardware
// signature must be valid, and when req carried an expected REPORTDATA the
// report_data_match verdict must be affirmatively true. For callers holding a
// response obtained through a fakeable Verify interface; callers with a
// concrete Client use [Client.VerifyEnforced].
func EnforceVerdict(req types.VerifyRequest, resp types.VerifyResponse) error {
	if !resp.Result.SignatureValid {
		return ErrSignatureInvalid
	}
	if req.Params != nil && req.Params.ExpectedReportData != nil {
		if resp.Result.ReportDataMatch == nil || !*resp.Result.ReportDataMatch {
			return ErrReportDataMismatch
		}
	}
	// The init-data pin is enforced on the in-process engine path
	// (internal/localverify Params.ExpectedInitDataHash), not on this delegated
	// one: wiring req.Params.ExpectedInitDataHash must add a matching
	// InitDataMatch gate here — see #89.
	return nil
}

// EvidencePolicy is the verification policy for [Client.VerifyEvidence].
type EvidencePolicy struct {
	// ExpectedReportData is the full 64-byte REPORTDATA the evidence must
	// bind (SHA-384 in bytes 0-47, zero-padded). The platform-specific wire
	// form is derived from it: the Azure TPM-nonce platforms (az-snp, az-tdx)
	// compare the exact 48-byte digest, the native platforms (snp, gcp-snp,
	// tdx) zero-pad whatever is sent and compare all 64 bytes.
	ExpectedReportData [64]byte

	// AllowDebug controls whether debug-mode guests are accepted.
	AllowDebug bool

	// MinTcb, when set, is the minimum platform TCB. Sent on the SNP paths
	// only: the attestation-api's TDX verifier has no minimum-TCB parameter.
	MinTcb *types.MinTcb

	// Entries pins whole images — a launch digest together with the registers
	// measured from the same build. When set it replaces Measurements and
	// RTMRs, so a digest from one image cannot be paired with another's.
	Entries []measurements.Entry

	// Measurements is the set of acceptable launch measurements; empty
	// accepts any (callers are expected to warn). The attestation-api
	// normalizes both the SNP LAUNCH_DIGEST and the TDX MRTD into
	// claims.launch_digest.
	Measurements [][]byte

	// RTMRs pins TDX runtime measurement registers by index, and is what makes
	// a TDX guest's own bytes attested rather than just its firmware's. MRTD
	// covers TDVF alone: TDVF measures the guest kernel into RTMR[1] and the
	// kernel command line — which carries the dm-verity root hash — into
	// RTMR[2], so without these a host can boot a different guest image and
	// still produce the pinned MRTD.
	//
	// Ignored on SNP, where the command line reaches the launch digest through
	// kernel-hashes. Absent indices are unpinned; RTMR[0] should stay that way,
	// as it carries the TD HOB and so varies with the pod's vCPU and memory
	// shape. RTMR[3] is extended by in-guest software and cannot speak to guest
	// identity — a substituted guest extends it with whatever it likes.
	RTMRs map[int][]byte
}

// VerifyEvidence verifies an attestation evidence envelope against policy via
// /verify, enforcing the verdict ([Client.VerifyEnforced]) plus the launch
// measurement reference values. Platforms without verification rules here fail
// closed with [ErrUnsupportedPlatform] rather than being approved under
// another platform's rules.
func (c Client) VerifyEvidence(ctx context.Context, evidence types.AttestationEvidence, policy EvidencePolicy) (types.VerifyResponse, error) {
	switch evidence.Platform {
	case string(types.PlatformSnp), string(types.PlatformAzSnp), string(types.PlatformGcpSnp):
		return c.verifySNPEvidence(ctx, evidence, policy)
	case string(types.PlatformTdx), string(types.PlatformAzTdx), string(types.PlatformGcpTdx):
		return c.verifyTDXEvidence(ctx, evidence, policy)
	default:
		return types.VerifyResponse{}, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, evidence.Platform)
	}
}

func (c Client) verifySNPEvidence(ctx context.Context, evidence types.AttestationEvidence, policy EvidencePolicy) (types.VerifyResponse, error) {
	// az-snp binds the key through a TPM quote whose nonce is the 48-byte
	// SHA-384 digest — it must receive exactly those 48 bytes. snp and
	// gcp-snp carry the native 64-byte REPORTDATA field and compare all 64.
	reportData := policy.ExpectedReportData[:]
	if evidence.Platform == string(types.PlatformAzSnp) {
		reportData = policy.ExpectedReportData[:sha512.Size384]
	}

	resp, err := c.VerifyEnforced(ctx, verifyRequest(evidence, reportData, policy.AllowDebug, policy.MinTcb))
	if err != nil {
		return types.VerifyResponse{}, err
	}
	if err := enforcePins(resp, policy, evidence.Platform); err != nil {
		return types.VerifyResponse{}, err
	}

	return resp, nil
}

// enforcePins applies whichever pin form the caller configured. Entries are
// matched whole; the flat pair keeps its own path so an operator who set only
// it sees exactly the decisions it always made.
func enforcePins(resp types.VerifyResponse, policy EvidencePolicy, platform string) error {
	if len(policy.Entries) > 0 {
		return EnforceEntries(resp, policy.Entries, platform)
	}
	if err := enforceLaunchMeasurement(resp, policy.Measurements); err != nil {
		return err
	}
	if TDXPlatform(platform) {
		return EnforceRTMRs(resp, policy.RTMRs)
	}
	return nil
}

func (c Client) verifyTDXEvidence(ctx context.Context, evidence types.AttestationEvidence, policy EvidencePolicy) (types.VerifyResponse, error) {
	// az-tdx binds the key through the vTPM quote whose nonce is the 48-byte
	// SHA-384 digest — it must receive exactly those 48 bytes, like az-snp.
	// Native tdx carries the 64-byte REPORTDATA field in the TD report and
	// compares all 64.
	reportData := policy.ExpectedReportData[:]
	if evidence.Platform == string(types.PlatformAzTdx) {
		reportData = policy.ExpectedReportData[:sha512.Size384]
	}

	// The attestation-api surfaces MRTD as claims.launch_digest, and the raw
	// RTMRs as hex in claims.platform_data. Both are enforced client-side, so
	// the policy stays here rather than being asserted by the verifier. MinTcb
	// is omitted because the c8s TDX request has no minimum-TCB policy field.
	resp, err := c.VerifyEnforced(ctx, verifyRequest(evidence, reportData, policy.AllowDebug, nil))
	if err != nil {
		return types.VerifyResponse{}, err
	}
	if err := enforcePins(resp, policy, evidence.Platform); err != nil {
		return types.VerifyResponse{}, err
	}
	return resp, nil
}

// TDXPlatform reports whether platform names TDX-shaped evidence, i.e. carries
// runtime measurement registers an RTMR pin can be enforced against. The
// family mapping is teetypes.Family, so a new TDX tag there (gcp-tdx today)
// gets its RTMRs enforced instead of silently skipping the pin.
func TDXPlatform(platform string) bool {
	return teetypes.NormalizePlatform(platform).IsTDX()
}

// EnforceRTMRs requires each pinned register to byte-equal the value the
// verifier reported. A pinned register the evidence does not carry is a
// refusal, not a pass: that is what an SNP quote (or a verifier that stopped
// reporting them) looks like, and neither says the guest is the expected one.
// Exported for issuance gates (CDS /attest, /attest-key) that verify evidence
// via [Client.VerifyEnforced] rather than [Client.VerifyEvidence]; such
// callers gate on [TDXPlatform] first, since RTMRs exist only there.
func EnforceRTMRs(resp types.VerifyResponse, pinned map[int][]byte) error {
	if len(pinned) == 0 {
		return nil
	}
	return enforceRTMRsAgainst(reportedRTMRs(resp), pinned)
}

// reportedRTMRs reads the registers the verifier reported. Shared with the
// entry matcher so the two cannot disagree about what evidence carries. An
// absent or non-string claim reads as "", which enforceRTMRsAgainst refuses
// for any pinned register.
func reportedRTMRs(resp types.VerifyResponse) [4]string {
	var out [4]string
	for i := range out {
		out[i], _ = resp.Result.Claims.PlatformData[fmt.Sprintf("rtmr_%d", i)].(string)
	}
	return out
}

func enforceRTMRsAgainst(reported [4]string, pinned map[int][]byte) error {
	for _, idx := range sortedRTMRIndices(pinned) {
		want := pinned[idx]
		if idx < 0 || idx >= len(reported) {
			return fmt.Errorf("%w: RTMR[%d] does not exist", ErrRTMRNotAllowed, idx)
		}
		if reported[idx] == "" {
			return fmt.Errorf("%w: RTMR[%d] pinned but not reported", ErrRTMRNotAllowed, idx)
		}
		got, err := hex.DecodeString(reported[idx])
		if err != nil {
			return fmt.Errorf("%w: RTMR[%d] is not hex: %w", ErrRTMRNotAllowed, idx, err)
		}
		if len(got) != launchMeasurementSize {
			return fmt.Errorf("%w: RTMR[%d] is %d bytes, expected %d", ErrRTMRNotAllowed, idx, len(got), launchMeasurementSize)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("%w: RTMR[%d] does not match", ErrRTMRNotAllowed, idx)
		}
	}
	return nil
}

// sortedRTMRIndices keeps the error an operator sees stable across runs.
func sortedRTMRIndices(pinned map[int][]byte) []int {
	idx := make([]int, 0, len(pinned))
	for i := range pinned {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	return idx
}

// enforceLaunchMeasurement validates the verifier's normalized launch digest
// and, when allowed is non-empty, requires it to match a caller reference value.
// For SNP the digest is LAUNCH_DIGEST; for TDX it is MRTD. Both are SHA-384.
func enforceLaunchMeasurement(resp types.VerifyResponse, allowed [][]byte) error {
	digest := resp.Result.Claims.LaunchDigest
	if digest == "" {
		if len(allowed) > 0 {
			return fmt.Errorf("%w: launch measurement missing", ErrMeasurementNotAllowed)
		}
		return nil
	}

	measurement, err := hex.DecodeString(digest)
	if err != nil {
		return fmt.Errorf("%w: launch digest is not hex: %w", ErrInvalidLaunchDigest, err)
	}
	if len(measurement) != launchMeasurementSize {
		return fmt.Errorf("%w: launch digest is %d bytes, expected %d", ErrInvalidLaunchDigest, len(measurement), launchMeasurementSize)
	}
	if len(allowed) > 0 && !MeasurementAllowed(measurement, allowed) {
		return fmt.Errorf("%w: launch measurement does not match any reference value", ErrMeasurementNotAllowed)
	}
	return nil
}

// verifyRequest builds the /verify request: expected REPORTDATA bound, token
// issuance off (c8s callers mint their own EAR after verifying).
func verifyRequest(evidence types.AttestationEvidence, reportData []byte, allowDebug bool, minTcb *types.MinTcb) types.VerifyRequest {
	expected := types.NewBase64Bytes(reportData)
	return types.NewVerifyRequest(evidence, &types.VerifyParams{
		ExpectedReportData: &expected,
		AllowDebug:         &allowDebug,
		MinTcb:             minTcb,
	}, false)
}

// MeasurementAllowed reports whether measurement byte-equals one of the
// reference launch digests (an empty set means "no pin" and is handled
// by callers).
func MeasurementAllowed(measurement []byte, allowed [][]byte) bool {
	for _, m := range allowed {
		if bytes.Equal(measurement, m) {
			return true
		}
	}
	return false
}
