package ratls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// VerifyPolicy defines what attestation claims are acceptable.
type VerifyPolicy struct {
	// Measurements is the set of acceptable launch measurements (48 bytes each).
	// If empty, any measurement is accepted (UNSAFE — use only for development).
	// For SNP this pins LAUNCH_DIGEST; for TDX it pins MRTD.
	Measurements [][]byte

	// RTMRs pins TDX runtime measurement registers by index. MRTD covers TDVF
	// alone, so on TDX it is these — RTMR[1] for the guest kernel, RTMR[2] for
	// the command line carrying the dm-verity root hash — that make the guest
	// image itself attested. Ignored on SNP, where kernel-hashes folds the
	// command line into the launch digest. Empty pins nothing.
	//
	// Leave RTMR[0] unpinned: it carries the TD HOB, so it varies with the
	// pod's vCPU and memory shape. RTMR[3] is extended by in-guest software and
	// so cannot speak to guest identity.
	RTMRs map[int][]byte

	// MinTCBVersion is the minimum acceptable platform TCB version.
	// This is a packed uint64 where each byte represents a component
	// (bootloader, TEE, reserved, snp, microcode, etc.) — each component
	// of the current TCB must be >= the corresponding minimum.
	// If zero, any TCB version is accepted.
	// Enforced on the SNP path only; dropped for TDX (see
	// attestationclient.EvidencePolicy).
	MinTCBVersion uint64

	// AllowDebug controls whether debug-mode guests are accepted.
	// Default: false (reject debug guests).
	AllowDebug bool

	// Nonce, when set, is verified against the attestation report's REPORTDATA.
	// REPORTDATA must equal hash(pubkey || nonce). Use when both sides agree on
	// a pre-shared nonce for additional freshness guarantees. If nil, no nonce
	// check is performed (TLS 1.3 already provides replay protection).
	Nonce []byte

	// SandboxID, when set, is the CRI pod sandbox ID the certificate's
	// sandbox-ID extension must carry (docs/ratls.md, "Sandbox identity").
	// Only [VerifyCert] can enforce it (the ID rides the certificate);
	// [VerifyAttestation] fails closed when it is set.
	SandboxID string

	// WorkloadName, when set, is the allowlist entry name the certificate's
	// matched-workload extension must carry (docs/ratls.md, "Matched
	// workload"). Like SandboxID it is CA-vouched: it is enforced only on the
	// chain-verified branch of the dual peer verifier, and VerifyAttestation /
	// VerifyCert fail closed when it is set — neither checks a CA chain, so
	// neither can authenticate the stamp.
	WorkloadName string

	// AttestationApiURL is the attestation-api whose /verify endpoint performs
	// all evidence verification: hardware signature chain, REPORTDATA key
	// binding, debug policy, and minimum TCB. Required: there is no
	// in-process verification path; verification without it fails closed.
	//
	// SECURITY: the /verify response is currently not signed; the verifier
	// trusts whatever this URL returns. Operators MUST point this at an
	// attestation-api inside the same TCB (e.g. the node-local Unix socket
	// the DaemonSet's attest-proxy serves, or an in-guest loopback service).
	// A response-signing scheme would lift this constraint.
	AttestationApiURL string

	// AttestationVerifyTimeout bounds online attestation-api verification.
	// If unset, a conservative default is used.
	AttestationVerifyTimeout time.Duration

	// RequireCAEvidence selects the production trust mode for the dual CA /
	// RA-TLS peer verifier (dualVerifyPeerCallback). When false (default), a
	// peer whose leaf chains to a configured CA is accepted on the CA chain
	// alone (a sandbox-ID pin is still enforced) — the legacy/dev mode that
	// eases rolling upgrades and CA rotation. When true, a valid CA chain is no
	// longer sufficient: the leaf must ALSO carry re-verifiable RA-TLS evidence
	// (issuer.SignCSR copies the requester's nonce-free .1.1 extension onto the
	// leaf), which is re-verified per connection so a CA compromise or wrong
	// issuance policy is caught at the peer rather than trusted from the chain.
	// The embedded evidence is nonce-free by construction (bound to the leaf
	// key and claims, no per-connection nonce); connection liveness comes from
	// the TLS 1.3 proof-of-possession of the leaf key. Set by the production
	// profile; a self-signed RA-TLS peer is unaffected (it always verifies its
	// evidence via the fallback path).
	RequireCAEvidence bool
}

// VerifyResult contains the verified attestation claims extracted from the cert.
type VerifyResult struct {
	// TEEType is the platform type.
	TEEType TEEType
	// ReportData is the 64-byte expected REPORTDATA that the attestation-api
	// confirmed the report is bound to (the api returns only a match verdict,
	// not the report bytes, so this echoes the verified expectation).
	ReportData [64]byte
	// Measurement is the 48-byte launch measurement reported by the
	// attestation-api: LAUNCH_DIGEST for SNP or MRTD for TDX.
	Measurement [48]byte
	// PlatformInfo contains platform-specific metadata from the
	// attestation-api response. Only set on the SNP path.
	PlatformInfo []byte
}

// VerifyAttestation verifies a raw attestation report against a public key by
// forwarding the evidence to the attestation-api /verify endpoint
// (policy.AttestationApiURL, required):
//  1. The attestation-api verifies the hardware signature chain and that
//     REPORTDATA == hash(pub || nonce), proving the key was generated inside
//     the TEE (and the report is fresh if nonce is set), plus the debug and
//     minimum-TCB policy.
//  2. The launch measurement it returns is checked against
//     policy.Measurements here, and any pinned TDX RTMRs against policy.RTMRs.
func VerifyAttestation(pub crypto.PublicKey, att *Attestation, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}
	if policy.AttestationApiURL == "" {
		return nil, fmt.Errorf("%w: attestation-api URL is required", ErrInvalidReport)
	}
	if policy.SandboxID != "" {
		// The ID rides the certificate, which this path never sees.
		return nil, fmt.Errorf("%w: sandbox-ID pin requires a CA-verified certificate", ErrPolicyViolation)
	}
	if policy.WorkloadName != "" {
		return nil, fmt.Errorf("%w: workload pin requires a CA-verified certificate", ErrPolicyViolation)
	}

	expectedReportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	return verifyReport(att, policy, expectedReportData)
}

// VerifyCert verifies an RA-TLS certificate: it extracts the TEE attestation
// extension and verifies it against the cert's public key.
//
// Trust comes from the hardware attestation chain (AMD ARK → ASK → VCEK, or
// Intel equivalent for TDX) as verified by the same-TCB attestation-api, not
// from any certificate authority signature. A sandbox-ID pin therefore cannot
// be enforced here: the ID rests on CDS's signature over the leaf, which this
// path does not check (docs/ratls.md, "Sandbox identity").
//
// The certificate body is authenticated first (certutil.AuthenticateLeafBody):
// the validity window (NotBefore within [certutil.LeafValiditySkew], NotAfter
// with no allowance), because the embedded evidence carries no per-connection
// nonce and the window is the only freshness bound this path has; and, for a
// self-issued leaf, its signature under its own attested key, because the
// attestation binds only the key — every other field could otherwise be
// rewritten under a genuine extension. Doing it before the evidence
// round-trip also keeps a bad certificate from consuming an attestation-api
// call.
func VerifyCert(cert *x509.Certificate, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}

	// Split out so a window failure keeps its own sentinel; callers
	// (dualVerifyPeerCallback, the mesh proxies) branch on ErrCertValidity.
	now := time.Now()
	if err := certutil.CheckValidity(cert, now); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertValidity, err)
	}
	// The classification is not actionable at this layer: both classes reach
	// here legitimately — the self-signed mesh peer, and (via
	// dualVerifyPeerCallback's RequireCAEvidence step) a CA-signed leaf whose
	// chain that caller has already verified. What the call buys is the
	// self-signature check on the self-issued case, which is the half of body
	// authentication this path would otherwise skip.
	if _, err := certutil.AuthenticateLeafBody(cert, now); err != nil {
		return nil, fmt.Errorf("ratls: peer certificate body: %w", err)
	}

	att, err := ExtractAttestation(cert)
	if err != nil {
		return nil, err
	}

	pub, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("ratls: extract public key: %w", err)
	}

	if policy.AttestationApiURL == "" {
		return nil, fmt.Errorf("%w: attestation-api URL is required", ErrInvalidReport)
	}
	if policy.SandboxID != "" {
		return nil, fmt.Errorf("%w: sandbox-ID pin requires a CA-verified certificate", ErrPolicyViolation)
	}
	if policy.WorkloadName != "" {
		return nil, fmt.Errorf("%w: workload pin requires a CA-verified certificate", ErrPolicyViolation)
	}

	expectedReportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	return verifyReport(att, policy, expectedReportData)
}

// CheckSandboxPin enforces expectedID against a leaf whose CA chain the caller
// has ALREADY verified. The ID is stamped by CDS into the signed area after it
// verifies the inventory-signed sandbox token, so the mesh CA signature — not
// the hardware evidence — is what authenticates it. Calling this on an
// unverified (e.g. self-signed) leaf would pin an attacker-chosen string.
//
// Empty expectedID is a no-op, so callers can invoke it unconditionally.
func CheckSandboxPin(cert *x509.Certificate, expectedID string) error {
	if expectedID == "" {
		return nil
	}
	id, err := SandboxIDFromCert(cert)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	}
	if id == "" {
		return fmt.Errorf("%w: sandbox-ID pin set but certificate carries no sandbox-ID extension", ErrPolicyViolation)
	}
	if id != expectedID {
		return fmt.Errorf("%w: certificate sandbox ID %q does not match pinned %q", ErrPolicyViolation, id, expectedID)
	}
	return nil
}

// ExtractAttestation finds and parses the RA-TLS extension from a certificate.
func ExtractAttestation(cert *x509.Certificate) (*Attestation, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDRATLSAttestation) {
			return UnmarshalExtension(ext.Value)
		}
	}
	return nil, fmt.Errorf("%w (OID %s)", ErrNotAttested, OIDRATLSAttestation)
}

// verifyReport normalizes the attestation into an evidence envelope and hands
// it to the attestation-api enforced verifier. The extension's TEE type must
// match the envelope's platform family — fail closed rather than approve one
// platform's evidence under another's rules.
func verifyReport(att *Attestation, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	evidence := att.embedded
	switch att.TEEType {
	case TEETypeSEVSNP:
		// Envelope platforms (az-snp) embed their evidence in the
		// extension directly; bare-metal SNP carries the raw report,
		// which is wrapped in the "snp" evidence envelope here.
		if evidence == nil {
			var err error
			if evidence, err = snpEvidence(att.Report); err != nil {
				return nil, err
			}
		}
		switch evidence.Platform {
		case string(types.PlatformSnp), string(types.PlatformAzSnp), string(types.PlatformGcpSnp):
		default:
			return nil, fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, evidence.Platform)
		}
	case TEETypeTDX:
		// TDX always carries a JSON envelope in the RA-TLS extension (see
		// extension.go's UnmarshalExtension). We do NOT ship an in-process
		// TDX quote parser — delegating keeps the heavy Intel dependencies
		// out of every c8s Go binary.
		if evidence == nil {
			return nil, fmt.Errorf("%w: TDX RA-TLS extension missing evidence envelope", ErrInvalidReport)
		}
		switch evidence.Platform {
		case string(types.PlatformTdx), string(types.PlatformAzTdx):
		default:
			return nil, fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, evidence.Platform)
		}
	default:
		return nil, fmt.Errorf("%w: TEE type %d", ErrUnsupportedTEE, att.TEEType)
	}
	return verifyEnvelopeOnline(evidence, policy, expectedReportData)
}

const defaultAttestationVerifyTimeout = 10 * time.Second

// unpackSNPMinTcb maps a packed AMD SEV-SNP TCB uint64 onto the components
// the attestation-api understands. Layout matches the SEV-SNP ABI
// TcbVersion: byte 0 = bootloader, byte 1 = tee, bytes 2-5 reserved,
// byte 6 = snp, byte 7 = microcode.
func unpackSNPMinTcb(packed uint64) types.MinTcb {
	return types.MinTcb{
		Bootloader: byte(packed),
		Tee:        byte(packed >> 8),
		Snp:        byte(packed >> 48),
		Microcode:  byte(packed >> 56),
	}
}

// verifyEnvelopeOnline forwards the envelope to the attestation-api enforced
// verifier ([attestationclient.Client.VerifyEvidence] — verdict gate,
// platform-specific REPORTDATA wire form, measurement reference values) and maps its
// verdicts onto this package's sentinels.
func verifyEnvelopeOnline(evidence *types.AttestationEvidence, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	timeout := policy.AttestationVerifyTimeout
	if timeout <= 0 {
		timeout = defaultAttestationVerifyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var minTcb *types.MinTcb
	if policy.MinTCBVersion != 0 {
		m := unpackSNPMinTcb(policy.MinTCBVersion)
		minTcb = &m
	}
	resp, err := attestationclient.NewClient(policy.AttestationApiURL).VerifyEvidence(ctx, *evidence, attestationclient.EvidencePolicy{
		ExpectedReportData: expectedReportData,
		AllowDebug:         policy.AllowDebug,
		MinTcb:             minTcb,
		Measurements:       policy.Measurements,
		RTMRs:              policy.RTMRs,
	})
	if err != nil {
		return nil, mapVerifyError(evidence.Platform, err)
	}

	teeType := TEETypeSEVSNP
	if evidence.Platform == string(types.PlatformTdx) || evidence.Platform == string(types.PlatformAzTdx) {
		teeType = TEETypeTDX
	}
	result := &VerifyResult{TEEType: teeType}
	if teeType == TEETypeSEVSNP && len(resp.Result.Claims.PlatformData) > 0 && !bytes.Equal(resp.Result.Claims.PlatformData, []byte("null")) {
		result.PlatformInfo = resp.Result.Claims.PlatformData
	}
	copy(result.ReportData[:], expectedReportData[:])
	if resp.Result.Claims.LaunchDigest != "" {
		// Hex validity and length were enforced by VerifyEvidence.
		measurement, _ := hex.DecodeString(resp.Result.Claims.LaunchDigest)
		copy(result.Measurement[:], measurement)
	}
	return result, nil
}

// mapVerifyError translates attestationclient verdict sentinels onto this
// package's error surface, preserving the pre-consolidation sentinels callers
// match with errors.Is.
func mapVerifyError(platform string, err error) error {
	switch {
	case errors.Is(err, attestationclient.ErrSignatureInvalid):
		return ErrSignatureInvalid
	case errors.Is(err, attestationclient.ErrReportDataMismatch):
		return fmt.Errorf("%w — key was not generated in this TEE", ErrKeyBinding)
	case errors.Is(err, attestationclient.ErrMeasurementNotAllowed):
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	case errors.Is(err, attestationclient.ErrInvalidLaunchDigest):
		return fmt.Errorf("%w: %v", ErrInvalidReport, err)
	case errors.Is(err, attestationclient.ErrUnsupportedPlatform):
		return fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, platform)
	default:
		return fmt.Errorf("ratls: online %s attestation verify: %w", platform, err)
	}
}

// snpEvidence wraps a raw SEV-SNP attestation report in the attestation-api's
// bare-metal "snp" evidence envelope for POST /verify. Only bare-metal SNP
// carries raw report bytes in the RA-TLS extension; every other platform
// carries the full envelope directly, so no wrapping is needed for them
// (att.embedded is populated by UnmarshalExtension in that case).
func snpEvidence(rawReport []byte) (*types.AttestationEvidence, error) {
	inner, err := json.Marshal(struct {
		AttestationReport string `json:"attestation_report"`
	}{base64.StdEncoding.EncodeToString(rawReport)})
	if err != nil {
		return nil, fmt.Errorf("ratls: build snp evidence: %w", err)
	}
	return &types.AttestationEvidence{
		Platform: string(types.PlatformSnp),
		Evidence: inner,
	}, nil
}
