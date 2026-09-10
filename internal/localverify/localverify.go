// Package localverify verifies attestation evidence in-process with
// attestation-go (the Go port of the attestation-rs engine the cluster runs),
// auto-detecting the platform from the envelope tag. It backs the
// operator-side tools (`c8s verify`, `c8s allowlist`); in-cluster components
// delegate to their same-TCB attestation-api instead
// (ratls.VerifyPolicy.AttestationApiURL).
package localverify

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
)

// KDS getter bounds: the retry backoff is capped so several attempts fit inside
// a caller's short verification deadline (upstream's 30s cap assumes a 2min
// budget), and the getter's own timeout backstops the fetch when the context
// carries no deadline.
const (
	kdsMaxRetryDelay = 8 * time.Second
	kdsMaxFetchTime  = 2 * time.Minute
)

// Params is the policy a Verify call enforces on the evidence.
type Params struct {
	// ExpectedReportData is the binding anchor, unpadded (48-byte SHA-384 for
	// c8s bindings): hardware verifiers zero-pad it per platform, and the
	// Azure vTPM verifiers compare it raw — pass it unpadded.
	ExpectedReportData []byte
	// AllowDebug accepts debug-enabled guests. Default false (reject).
	AllowDebug bool
	// MinTCB, when set, is the minimum acceptable SNP TCB per component.
	MinTCB *teetypes.SnpTcb
	// Measurements pins the launch digest (SNP MEASUREMENT / TDX MR_TD).
	// Empty = no pin; with a pin, a missing launch digest fails closed.
	Measurements [][]byte
	// ExpectedInitDataHash, when set, pins the init-data digest: the engine
	// compares it against SNP HOST_DATA, TDX MRCONFIGID (zero-padded to 48),
	// or the az vTPM PCR[8] binding, and a mismatch fails verification.
	ExpectedInitDataHash []byte
}

// VerifyFunc is the signature of [Verify], taken as a parameter by consumers
// so tests can stub it.
type VerifyFunc func(ctx context.Context, platform string, evidence json.RawMessage, p Params) (*teetypes.VerificationResult, error)

// CollateralError marks a failure to obtain verification collateral (AMD KDS
// unreachable, context expired): no verdict was reached. Every other Verify
// error is a verdict — evidence was obtained and rejected.
type CollateralError struct{ Err error }

func (e *CollateralError) Error() string { return e.Err.Error() }
func (e *CollateralError) Unwrap() error { return e.Err }

// ErrMeasurementNotAllowed reports a launch digest outside Params.Measurements.
var ErrMeasurementNotAllowed = errors.New("launch measurement not in the allowed set")

// Verify verifies a self-describing evidence envelope and enforces p. The
// chain, binding, debug, min-TCB, and init-data checks are attestation-go's
// verdict; the measurement pin is enforced here on its claims. ctx bounds any
// AMD KDS collateral fetch.
func Verify(ctx context.Context, platform string, evidence json.RawMessage, p Params) (*teetypes.VerificationResult, error) {
	params := teetypes.VerifyParams{
		ExpectedReportData:   p.ExpectedReportData,
		ExpectedInitDataHash: p.ExpectedInitDataHash,
		AllowDebug:           p.AllowDebug,
		MinTCB:               p.MinTCB,
	}

	envelope, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.NormalizePlatform(platform),
		Evidence: evidence,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal evidence envelope: %w", err)
	}
	// A bare RA-TLS serving cert carries the SNP report with no inline VCEK;
	// the Getter lets the snp and gcp-snp arms fetch it from AMD KDS, bounded
	// by ctx. Nothing else here reaches the network.
	res, err := teeverify.VerifyWithOptionsContext(ctx, envelope, params, teeverify.Options{
		SNP: snp.Options{Getter: snp.DefaultKDSGetter(kdsMaxFetchTime, kdsMaxRetryDelay)},
	})
	if err != nil {
		var re *trust.AttestationRecreationErr
		if errors.Is(err, snp.ErrCollateralUnavailable) || errors.As(err, &re) {
			return nil, &CollateralError{Err: err}
		}
		// attestation-go returns an error (not a false verdict) on a bad
		// signature, chain, policy, or REPORTDATA mismatch — a
		// reachable-but-rejected outcome, i.e. a security verdict.
		return nil, err
	}
	if err := enforceResult(res, p); err != nil {
		return nil, err
	}
	return res, nil
}

// enforceResult re-checks the verdict against p on the verifier's own claims.
// A nil verification error already implies these checks; re-running them keeps
// a result that contradicts itself from reading as a success.
func enforceResult(res *teetypes.VerificationResult, p Params) error {
	if !res.SignatureValid {
		return fmt.Errorf("verifier returned signature_valid=false")
	}
	if p.ExpectedReportData != nil && (res.ReportDataMatch == nil || !*res.ReportDataMatch) {
		return fmt.Errorf("REPORTDATA does not match the expected binding (report_data_match not true)")
	}
	if p.ExpectedInitDataHash != nil && (res.InitDataMatch == nil || !*res.InitDataMatch) {
		return fmt.Errorf("init-data digest does not match the expected binding (init_data_match not true)")
	}
	if len(p.Measurements) > 0 {
		mb, err := hex.DecodeString(res.Claims.LaunchDigest)
		if err != nil || len(mb) == 0 {
			return fmt.Errorf("cannot enforce the measurement pin: launch digest missing or malformed (%q)", res.Claims.LaunchDigest)
		}
		if !attestationclient.MeasurementAllowed(mb, p.Measurements) {
			return fmt.Errorf("%w (launch digest %s)", ErrMeasurementNotAllowed, res.Claims.LaunchDigest)
		}
	}
	return nil
}

// CertEnvelope extracts the RA-TLS attestation from a certificate and returns
// the evidence envelope plus the expected REPORTDATA anchor — SHA-384 over the
// public key (no per-request nonce, so no freshness proof).
//
// An extension carrying a full envelope (az-snp, TDX) is forwarded verbatim; a
// raw SEV-SNP report is wrapped as {attestation_report, cert_chain.vcek?}, with
// the VCEK inline when the extension carried one.
func CertEnvelope(cert *x509.Certificate) (platform string, evidence json.RawMessage, expectedReportData []byte, err error) {
	att, err := ratls.ExtractAttestation(cert)
	if err != nil {
		return "", nil, nil, err
	}
	env, err := att.Envelope()
	if err != nil {
		return "", nil, nil, err
	}
	rd, err := agratls.ReportDataForKey(cert.PublicKey, nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("compute expected REPORTDATA: %w", err)
	}
	return string(env.Platform), env.Evidence, rd[:sha512.Size384], nil
}
