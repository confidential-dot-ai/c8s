// Package localverify verifies attestation evidence in-process with
// attestation-go (the Go port of the attestation-rs engine the cluster runs),
// auto-detecting the platform from the envelope tag. It backs the
// operator-side tools (`c8s verify`, `c8s allowlist`); in-cluster components
// delegate to their same-TCB attestation-api instead
// (ratls.VerifyPolicy.AttestationApiURL).
package localverify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
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
	// Azure vTPM verifiers compare it raw (see docs/pitfalls.md — "pass it
	// unpadded").
	ExpectedReportData []byte
	// AllowDebug accepts debug-enabled guests. Default false (reject).
	AllowDebug bool
	// MinTCB, when set, is the minimum acceptable SNP TCB per component.
	MinTCB *teetypes.SnpTcb
	// Measurements pins the launch digest (SNP MEASUREMENT / TDX MR_TD).
	// Empty = no pin; with a pin, a missing launch digest fails closed.
	//
	// On TDX this pins MRTD, which measures the TDVF firmware's measured
	// regions and NOTHING ELSE — not the kernel, not the rootfs. Two entirely
	// different guest images built against the same firmware share an MRTD, so
	// a measurement pin alone does not establish which OS booted. That lives in
	// ExpectedRTMRs[1] and [2].
	Measurements [][]byte
	// ExpectedRTMRs pins the TDX runtime measurement registers by index; a nil
	// entry skips that register. Each non-nil entry is 48 bytes.
	//
	//	[0] firmware/config events (not currently pinned by c8s)
	//	[1] UKI PE image identity + GPT + boot — the guest kernel
	//	[2] the UKI section measurement chain — the guest rootfs
	//	[3] runtime extends: the operator-key seed and any per-workload
	//	    measurements chained onto it (pkg/runtimemeasure)
	//
	// [1] and [2] answer "which image booted", and their reference values come
	// from the confos build manifest published alongside the image. [3] answers
	// "whose deployment is this". Together with Measurements they are what makes
	// a verdict specific rather than "some genuine TEE running some c8s build".
	//
	// TDX only: SNP has no runtime-extend registers, and attestation-go consults
	// RTMR pins only on the TDX path, so a pin set against any other platform
	// would be silently ignored. Verify rejects that rather than reporting a
	// pass nothing enforced.
	ExpectedRTMRs [4][]byte
}

// rtmrMeaning labels each register for error messages, so a mismatch says what
// actually differs rather than quoting a bare index.
var rtmrMeaning = [4]string{
	"firmware/config events",
	"guest kernel (UKI image identity)",
	"guest rootfs (UKI section chain)",
	"runtime extends (operator key / workloads)",
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

// ErrRTMRNotAllowed reports a runtime measurement register that does not match
// the corresponding Params.ExpectedRTMRs entry: a different guest image booted
// ([1]/[2]), or the node was not launched to trust the pinned operator key
// ([3]).
var ErrRTMRNotAllowed = errors.New("runtime measurement register does not match the expected value")

// Verify verifies a self-describing evidence envelope and enforces p. The
// chain, binding, debug, and min-TCB checks are attestation-go's verdict; the
// measurement pin is enforced here on its claims. ctx bounds any AMD KDS
// collateral fetch.
func Verify(ctx context.Context, platform string, evidence json.RawMessage, p Params) (*teetypes.VerificationResult, error) {
	params := teetypes.VerifyParams{
		ExpectedReportData: p.ExpectedReportData,
		AllowDebug:         p.AllowDebug,
		MinTCB:             p.MinTCB,
	}
	for i, want := range p.ExpectedRTMRs {
		if want == nil {
			continue
		}
		if len(want) != runtimemeasure.Size {
			return nil, fmt.Errorf("expected RTMR[%d] is %d bytes, want %d", i, len(want), runtimemeasure.Size)
		}
		// The registers are TDX-only, and attestation-go consults RTMR pins only
		// on the TDX path — accepting one for any other platform would drop it
		// silently, leaving a pin that looks configured and enforces nothing.
		if platform != string(teetypes.PlatformTDX) {
			return nil, fmt.Errorf("platform is %q: runtime measurement registers are TDX-only, so an RTMR[%d] pin cannot be enforced here", platform, i)
		}
		// Deliberately NOT passed down as teetypes.ExpectedRTMRs: go-tdx-guest
		// would reject the mismatch first, and its message reports the register
		// 1-based ("RTMR[4]" for RTMR[3]) without naming what actually differs,
		// which reads as a hardware fault rather than an identity mismatch.
		// Enforced below on the signature-verified claims instead — the same
		// posture the --measurements pin uses, and the same one `confai verify`
		// and `c8s get-kubeconfig` already take for RTMR[3].
	}

	res, err := dispatch(ctx, platform, evidence, params)
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
	// Defense in depth: a nil error already implies these, but never report a
	// success the result contradicts.
	if !res.SignatureValid {
		return nil, fmt.Errorf("verifier returned signature_valid=false")
	}
	if params.ExpectedReportData != nil && (res.ReportDataMatch == nil || !*res.ReportDataMatch) {
		return nil, fmt.Errorf("REPORTDATA does not match the expected binding (report_data_match not true)")
	}
	if len(p.Measurements) > 0 {
		mb, err := hex.DecodeString(res.Claims.LaunchDigest)
		if err != nil || len(mb) == 0 {
			return nil, fmt.Errorf("cannot enforce the measurement pin: launch digest missing or malformed (%q)", res.Claims.LaunchDigest)
		}
		if !ratls.MeasurementAllowed(mb, p.Measurements) {
			return nil, fmt.Errorf("%w (launch digest %s)", ErrMeasurementNotAllowed, res.Claims.LaunchDigest)
		}
	}
	// The rtmr_N claims are read off the signature-verified quote body, so
	// comparing them here is as strong as a check inside the quote parser — and
	// it can say what actually went wrong. Missing or malformed fails closed.
	for i, want := range p.ExpectedRTMRs {
		if want == nil {
			continue
		}
		key := fmt.Sprintf("rtmr_%d", i)
		got, _ := res.Claims.PlatformData[key].(string)
		got = strings.ToLower(strings.TrimSpace(got))
		if got == "" {
			return nil, fmt.Errorf("%w: quote carries no %s (is this a TDX guest with runtime measurement?)", ErrRTMRNotAllowed, key)
		}
		gb, err := hex.DecodeString(got)
		if err != nil {
			return nil, fmt.Errorf("%w: %s claim is malformed (%q)", ErrRTMRNotAllowed, key, got)
		}
		if !bytes.Equal(gb, want) {
			return nil, fmt.Errorf("%w: RTMR[%d] (%s) is %s, expected %s",
				ErrRTMRNotAllowed, i, rtmrMeaning[i], got, hex.EncodeToString(want))
		}
	}
	return res, nil
}

// dispatch routes evidence to attestation-go. The envelope path
// (teeverify.Verify) verifies offline and is used whenever the VCEK is already
// inline (a discovery doc or endpoint response). A bare RA-TLS serving cert
// carries the SNP report but no VCEK, and the envelope path requires it inline
// (attestation-go does no KDS fetch there); for that case we drop to
// snp.VerifyReportContext with a KDS Getter — it resolves the product from the
// report (Zen4c/Siena-aware) and fetches the VCEK from AMD KDS itself, bounded
// by ctx.
func dispatch(ctx context.Context, platform string, evidence json.RawMessage, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
	if mayMissVCEK(platform) {
		var se snp.SnpEvidence
		if err := json.Unmarshal(evidence, &se); err != nil {
			return nil, fmt.Errorf("parse snp evidence: %w", err)
		}
		if se.CertChain == nil || se.CertChain.Vcek == "" {
			report, err := base64.StdEncoding.DecodeString(se.AttestationReport)
			if err != nil {
				return nil, fmt.Errorf("decode attestation_report: %w", err)
			}
			// nil VCEK + a Getter ⇒ attestation-go fetches the VCEK from AMD KDS,
			// retrying until ctx or the backstop expires, whichever is sooner.
			getter := &trust.RetryHTTPSGetter{
				Timeout:       kdsMaxFetchTime,
				MaxRetryDelay: kdsMaxRetryDelay,
				Getter:        &trust.SimpleHTTPSGetter{},
			}
			return snp.VerifyReportContext(ctx, report, nil, params,
				teetypes.PlatformType(platform), snp.MinReportVersion,
				snp.Options{Getter: getter})
		}
	}

	envelope, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformType(platform),
		Evidence: evidence,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal evidence envelope: %w", err)
	}
	return teeverify.Verify(envelope, params)
}

// mayMissVCEK reports whether evidence for this platform might lack the VCEK the
// bare-cert path needs (so we fetch it from AMD KDS). True for bare-metal/GCP
// SEV-SNP, whose {attestation_report, cert_chain?} object can omit it. az-snp
// always ships the VCEK inside its HCL-report envelope, and TDX has no VCEK —
// both verify through the envelope path (teeverify.Verify) directly.
func mayMissVCEK(platform string) bool {
	return platform == "snp" || platform == "gcp-snp"
}

// CertEnvelope extracts the RA-TLS attestation from a certificate and returns
// the evidence envelope plus the expected REPORTDATA anchor — SHA-384 over the
// public key and any config-claims extension the cert carries (no per-request
// nonce, so no freshness proof).
func CertEnvelope(cert *x509.Certificate) (platform string, evidence json.RawMessage, expectedReportData []byte, err error) {
	att, err := ratls.ExtractAttestation(cert)
	if err != nil {
		return "", nil, nil, err
	}
	platform, evidence, err = EnvelopeFromAttestation(att)
	if err != nil {
		return "", nil, nil, err
	}
	rd, err := ratls.ReportDataForKeyAndClaims(cert.PublicKey, ratls.ExtractConfigClaimsBytes(cert), nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("compute expected REPORTDATA: %w", err)
	}
	return platform, evidence, rd[:sha512.Size384], nil
}

// EnvelopeFromAttestation turns an RA-TLS cert's embedded attestation into the
// platform + evidence object the verifier expects. An embedded {platform,
// evidence} envelope (e.g. az-snp) is forwarded verbatim; a raw SEV-SNP report
// is wrapped as {attestation_report, cert_chain.vcek?}. A raw TDX report has no
// evidence shape wired here — use the discovery / attestation endpoint, which
// carries the attester's evidence object directly.
func EnvelopeFromAttestation(att *ratls.Attestation) (string, json.RawMessage, error) {
	if env, ok := att.EmbeddedEvidence(); ok {
		return env.Platform, env.Evidence, nil
	}
	switch att.TEEType {
	case ratls.TEETypeSEVSNP:
		inner := map[string]any{"attestation_report": base64.StdEncoding.EncodeToString(att.Report)}
		if len(att.CertChain) > 0 {
			inner["cert_chain"] = map[string]any{"vcek": base64.StdEncoding.EncodeToString(att.CertChain)}
		}
		raw, err := json.Marshal(inner)
		if err != nil {
			return "", nil, fmt.Errorf("marshal snp evidence: %w", err)
		}
		return string(types.PlatformSnp), raw, nil
	case ratls.TEETypeTDX:
		return "", nil, fmt.Errorf("verifying a raw TDX report from an RA-TLS serving cert is not yet supported; use the discovery or attestation endpoint")
	default:
		return "", nil, fmt.Errorf("unsupported TEE type %d", att.TEEType)
	}
}
