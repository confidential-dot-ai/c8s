package ratls

import "fmt"

// NormalizeSEVSNPReport validates the raw AMD SEV-SNP report size.
func NormalizeSEVSNPReport(raw []byte) ([]byte, error) {
	if len(raw) != SNPReportSize {
		return nil, fmt.Errorf("%w: not a raw %d-byte SEV-SNP report", ErrInvalidReport, SNPReportSize)
	}
	return raw, nil
}
