package ratls

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseHexMeasurements parses a comma-separated list of hex-encoded SEV-SNP
// launch digests into the byte form VerifyPolicy.Measurements expects. Empty
// input returns nil; the caller decides whether to warn.
func ParseHexMeasurements(raw string) ([][]byte, error) {
	return ParseHexMeasurementsList(strings.Split(raw, ","))
}

// ParseHexMeasurementsList parses a slice of hex-encoded SEV-SNP launch
// digests into the byte form VerifyPolicy.Measurements expects. Blank entries
// are skipped; an all-blank or empty slice returns nil. The caller decides
// whether to warn on an empty result.
func ParseHexMeasurementsList(raw []string) ([][]byte, error) {
	out := make([][]byte, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		decoded, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid hex measurement %q: %w", p, err)
		}
		if len(decoded) != SNPMeasurementSize {
			return nil, fmt.Errorf("measurement %q is %d bytes, want %d", p, len(decoded), SNPMeasurementSize)
		}
		out = append(out, decoded)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
