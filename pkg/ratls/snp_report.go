package ratls

import (
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/tpmcommon"
)

// NormalizeSEVSNPReport returns a raw AMD SEV-SNP report. AKS az-snp evidence
// may wrap the report in a Hyper-V HCL envelope; bare-metal SNP already returns
// the raw 1184-byte report.
func NormalizeSEVSNPReport(raw []byte) ([]byte, error) {
	if len(raw) == SNPReportSize {
		return raw, nil
	}
	hcl, err := tpmcommon.ParseHCLReport(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: not a raw %d-byte SEV-SNP report: %v", ErrInvalidReport, SNPReportSize, err)
	}
	if hcl.ReportType != tpmcommon.HCLReportTypeSNP {
		return nil, fmt.Errorf("%w: HCL envelope carries report type %d, want SNP (%d)", ErrInvalidReport, hcl.ReportType, tpmcommon.HCLReportTypeSNP)
	}
	return hcl.TEEReport, nil
}
