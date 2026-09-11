package attestclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// snpReportEnvelope holds the fields we care about inside the inner evidence
// blob returned by the attestation-api. Bare-metal SNP carries the raw
// report under attestation_report (standard base64).
type snpReportEnvelope struct {
	AttestationReport string `json:"attestation_report"`
}

// ExtractSNPReport returns the raw SNP report bytes (as a string) from the
// attestation-api's evidence envelope, picking the right field and
// base64 alphabet for the platform. Callers feed this into raTLS as the
// per-connection self-attestation payload.
func ExtractSNPReport(resp types.AttestResponse) (string, error) {
	var envelope snpReportEnvelope
	if err := json.Unmarshal(resp.Evidence, &envelope); err != nil {
		return "", fmt.Errorf("parse attestation evidence: %w", err)
	}

	switch {
	case envelope.AttestationReport != "":
		raw, err := base64.StdEncoding.DecodeString(envelope.AttestationReport)
		if err != nil {
			return "", fmt.Errorf("decode attestation_report: %w", err)
		}
		return string(raw), nil
	default:
		return "", fmt.Errorf("attestation evidence contains no attestation_report (platform: %s)", resp.Platform)
	}
}
