package attestclient

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

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
