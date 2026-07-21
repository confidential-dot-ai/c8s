package attestclient

import (
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// MakeSNPRATLSAttestFunc returns an RA-TLS AttestFunc (matching
// pkg/ratls.ServerConfig.AttestFunc) that asks an attestation-api for
// an SEV-SNP report binding the serving key. customData is the hex-encoded
// REPORTDATA the ratls TLS handshake passes in; only the leading SHA-384
// bytes are sent to the service to match the SNP report layout.
//
// The name says SNP but the body is platform-agnostic — RATLSEvidence
// dispatches on resp.Platform. TDX guests use it too; the SNP-shaped
// truncation to 48 bytes is harmless for TDX because ReportDataForKey
// zero-pads its 48-byte SHA-384 hash to the 64-byte REPORTDATA field.
func MakeSNPRATLSAttestFunc(client Client, attestationApiURL string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, customData string) (string, error) {
		reportDataBytes, err := hex.DecodeString(customData)
		if err != nil {
			return "", fmt.Errorf("decode report data hex: %w", err)
		}
		reportDataBytes = reportDataBytes[:sha512.Size384]
		resp, err := client.GenerateEvidenceContext(ctx, attestationApiURL, reportDataBytes)
		if err != nil {
			return "", fmt.Errorf("attestation-api: %w", err)
		}
		return RATLSEvidence(resp)
	}
}

// TEETypeForPlatform maps an attestation-api platform string to the RA-TLS
// extension's TEEType: the SNP variants (bare-metal, Azure, GCP) are SEV-SNP,
// the TDX variants are TDX. The RA-TLS extension records only the family; the
// per-variant evidence shape is auto-detected by ratls.UnmarshalExtension.
func TEETypeForPlatform(platform string) (ratls.TEEType, error) {
	switch types.Platform(platform) {
	case types.PlatformSnp, types.PlatformAzSnp, types.PlatformGcpSnp:
		return ratls.TEETypeSEVSNP, nil
	case types.PlatformTdx, types.PlatformAzTdx:
		return ratls.TEETypeTDX, nil
	default:
		return 0, fmt.Errorf("attestclient: no RA-TLS TEE type for platform %q", platform)
	}
}

// AttestationExtensionForClaims builds a nonce-free RA-TLS attestation
// extension binding pub and the config-claims DER via the local
// attestation-api, for embedding in a CSR (docs/ratls.md). CDS copies the
// extension onto the issued leaf, which is how a workload leaf carries hardware
// evidence a verifier can check against the leaf's config-claims — the same
// embed the mesh client uses for its own leaf (cdsclient.attestationExtension),
// with the claims folded in. It is nonce-free by design: the serving cert
// carries no per-request nonce, so [ratls.VerifyCert] recomputes the anchor
// with nonce=nil. claimsDER nil binds the key alone.
func (c Client) AttestationExtensionForClaims(ctx context.Context, attestationApiURL string, pub crypto.PublicKey, claimsDER []byte) (pkix.Extension, error) {
	reportData, err := ratls.ReportDataForKeyAndClaims(pub, claimsDER, nil)
	if err != nil {
		return pkix.Extension{}, err
	}
	resp, err := c.GenerateEvidenceContext(ctx, attestationApiURL, reportData[:sha512.Size384])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("attestation-api: %w", err)
	}
	report, err := RATLSEvidence(resp)
	if err != nil {
		return pkix.Extension{}, err
	}
	teeType, err := TEETypeForPlatform(resp.Platform)
	if err != nil {
		return pkix.Extension{}, err
	}
	att := &ratls.Attestation{TEEType: teeType, Report: []byte(report)}
	return att.MarshalExtension()
}

// RATLSEvidence returns the payload to embed in an RA-TLS certificate
// extension. Two shapes exist by design:
//
//   - Bare-metal SNP: raw SNP report bytes (extractable offline from an SNP
//     verifier). Kept as raw bytes for wire-compat + so bare-metal callers
//     don't need a running attestation-api at verify time.
//   - Everything else (az-snp, tdx, az-tdx): the attestation-api evidence
//     envelope. Verification forwards the envelope back to a local
//     attestation-api /verify — the source of truth for the quote's
//     signature + REPORTDATA match. Keeping a second in-process quote
//     parser in Go would silently drift from attestation-rs.
//
// For TDX, cc_eventlog is stripped from the envelope before embedding —
// see stripTDXEventlog for why.
//
// UnmarshalExtension auto-detects the envelope form (JSON leading '{')
// vs raw report bytes, so the two shapes coexist behind the same OID.
func RATLSEvidence(resp types.AttestResponse) (string, error) {
	if resp.Platform == string(types.PlatformSnp) {
		return ExtractSNPReport(resp)
	}

	envelope := types.AttestationEvidence(resp)
	if resp.Platform == string(types.PlatformTdx) {
		stripped, err := stripTDXEventlog(envelope.Evidence)
		if err != nil {
			return "", err
		}
		envelope.Evidence = stripped
	}

	evidence, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal RA-TLS attestation evidence: %w", err)
	}
	return string(evidence), nil
}
