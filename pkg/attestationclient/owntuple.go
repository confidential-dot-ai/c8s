package attestationclient

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// OwnTupleEntry attests the calling TD through c and returns the image tuple
// the verifier reports for it: MRTD as the digest and RTMR[1..3]. The
// evidence is bound to a fresh nonce and its verdict enforced (signature and
// REPORTDATA), so the tuple is this TD's now, not a replay. A peer pinned to
// the entry is accepted only when it runs the same image with the same
// runtime chain, which lets a sealed node pin CDS without any per-cluster
// digest in its own configuration. Non-TDX evidence is refused: only TDX
// carries the registers.
func (c Client) OwnTupleEntry(ctx context.Context) (measurements.Entry, error) {
	// The tuple is trusted as this node's because the verifier is the node's
	// own; a routable endpoint is one the control plane can substitute.
	if c.baseURL != unixBaseURL {
		return measurements.Entry{}, errors.New("OwnTupleEntry needs a unix:// verifier: a network endpoint is one the control plane can substitute")
	}
	// The attester takes the 48-byte prefix and zero-extends it into the
	// 64-byte REPORTDATA the verifier compares.
	var reportData [64]byte
	if _, err := rand.Read(reportData[:sha512.Size384]); err != nil {
		return measurements.Entry{}, fmt.Errorf("self-attest nonce: %w", err)
	}
	resp, err := c.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportData[:sha512.Size384]),
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		return measurements.Entry{}, fmt.Errorf("attest self: %w", err)
	}
	if !TDXPlatform(resp.Platform) {
		return measurements.Entry{}, fmt.Errorf("attestation-api reports platform %q, want TDX: only TDX evidence carries the runtime registers", resp.Platform)
	}
	verified, err := c.VerifyEvidence(ctx, types.AttestationEvidence(resp), EvidencePolicy{ExpectedReportData: reportData})
	if err != nil {
		return measurements.Entry{}, fmt.Errorf("verify self-report: %w", err)
	}
	return tupleEntry(verified)
}

// tupleEntry reads the MRTD and RTMR[1..3] out of a verified self-report,
// from the claims EnforceEntries later matches a peer's evidence against.
// RTMR[0] is left unpinned: it carries the TD HOB and varies with the VM's
// vCPU and memory shape.
func tupleEntry(resp types.VerifyResponse) (measurements.Entry, error) {
	mrtd, err := launchDigest(resp)
	if err != nil {
		return measurements.Entry{}, fmt.Errorf("self-report launch digest: %w", err)
	}
	entry := measurements.Entry{Name: "own-tuple", Digest: mrtd, RTMRs: map[int][]byte{}}
	reported := reportedRTMRs(resp)
	for i := 1; i <= 3; i++ {
		reg, err := hex.DecodeString(strings.TrimSpace(reported[i]))
		if err != nil || len(reg) != launchMeasurementSize {
			return measurements.Entry{}, fmt.Errorf("self-report rtmr_%d %q is not %d hex bytes", i, reported[i], launchMeasurementSize)
		}
		entry.RTMRs[i] = reg
	}
	return entry, nil
}
