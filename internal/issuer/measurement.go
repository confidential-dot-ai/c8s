package issuer

import "strings"

// NormalizeMeasurement canonicalizes launch digest strings before allowlist
// comparison. Attestation services may return hex digests in either case.
func NormalizeMeasurement(measurement string) string {
	return strings.ToLower(strings.TrimSpace(measurement))
}
