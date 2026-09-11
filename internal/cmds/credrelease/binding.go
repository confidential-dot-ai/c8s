// Package credrelease implements the in-guest credential-release service (B4
// of the operator-key design). It issues an operator a short-lived kube client
// certificate, but only to a caller who proves possession of the operator
// private key whose public half was bound into the CVM's launch identity at
// launch — giving an external operator
// console-free, non-TOFU admin access with no pre-shared cluster secret and
// no trust in the untrusted host.
package credrelease

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key it read off the opkeydata disk (and hashed into the launch binding). The
// service reads this file rather than mounting the ISO itself — mounting fails
// under the unit's systemd hardening, and the initrd is the single, measured
// reader of the disk anyway.
// Var (not const) so tests can point it at a temp file.
var operatorPubkeyPath = "/etc/confai/operator-pubkey"

// readOperatorPubkey reads the operator public key the initrd staged off the
// opkeydata disk. The bytes are exactly what the initrd hashed into the launch
// binding, so runtimemeasure can re-derive the same digest. Absence means the
// VM was launched without an operator key (no opkeydata disk).
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

// selfReportTimeout bounds the self-attestation round trip against the local
// attestation-api; on expiry the service fails start and systemd retries.
const selfReportTimeout = 15 * time.Second

// verifiedSelfReport returns this guest's own attestation as the local
// attestation-api verified it.
//
// Reading the launch binding off an UNVERIFIED report would take the anchor
// from an unauthenticated field, so the report goes through /verify even though
// the guest produced it. The anchor is a fresh nonce, which makes the report
// non-replayable for free.
func verifiedSelfReport(ctx context.Context, attestationAPIURL string) (*teetypes.VerificationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, selfReportTimeout)
	defer cancel()

	// The attester is asked for the 48-byte prefix and zero-extends it into the
	// 64-byte report data the verifier must find.
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
	return &verified.Result, nil
}

// LoadMeasuredOperatorKey reads the operator pubkey the initrd staged off the
// opkeydata disk and confirms the guest was launched to trust it. The returned
// bytes are safe to treat as the authorized operator key.
//
// This is the load-bearing anchor check: the pubkey file is NOT itself
// measured, only its digest, so before trusting the on-disk key the service
// confirms it is the key the launch bound. A host that swapped the file
// post-boot produces a mismatch — it can forge neither the register the
// measured initrd extended nor the field the launcher committed at launch.
//
// Which field carries the binding, and how wide it is, is runtimemeasure's
// problem: this reads the verified report and asks whether it names this key.
// Workload digests are nil because the node image runs no workload measurer, so
// the binding must equal the bare seed exactly; any extension beyond it means
// an unexpected measurer ran, and the comparison fails closed.
//
// Called once at service start; the binding is fixed for the life of the guest.
func LoadMeasuredOperatorKey(ctx context.Context, attestationAPIURL string) ([]byte, error) {
	pub, err := readOperatorPubkey()
	if err != nil {
		return nil, err
	}
	// The platform comes from the verified report, not from configuration: a
	// config string says which platform an operator EXPECTED, and the anchor
	// check must key off what the hardware actually proved.
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return nil, err
	}
	if err := runtimemeasure.VerifyBinding(report, pub, nil); err != nil {
		return nil, err
	}
	return pub, nil
}
