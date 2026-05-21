package ratls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const hclReportMagic = "HCLA"

// azureHCLHeader is the 32-byte little-endian header that AKS prepends to
// raw hardware attestation reports in az-snp evidence.
type azureHCLHeader struct {
	Signature   [4]byte
	Version     uint32
	PayloadSize uint32
	RequestType uint32
	Status      [4]byte
	Reserved    [12]byte
}

// NormalizeSEVSNPReport returns a raw AMD SEV-SNP report. AKS az-snp evidence
// may wrap the report in a Hyper-V HCL envelope; bare-metal SNP already returns
// the raw 1184-byte report.
func NormalizeSEVSNPReport(raw []byte) ([]byte, error) {
	if len(raw) == SNPReportSize {
		return raw, nil
	}

	headerSize := binary.Size(azureHCLHeader{})
	if len(raw) >= headerSize {
		var hdr azureHCLHeader
		if err := binary.Read(bytes.NewReader(raw[:headerSize]), binary.LittleEndian, &hdr); err != nil {
			return nil, fmt.Errorf("%w: parse HCL header: %w", ErrInvalidReport, err)
		}
		if bytes.Equal(hdr.Signature[:], []byte(hclReportMagic)) {
			end := headerSize + SNPReportSize
			if len(raw) < end {
				return nil, fmt.Errorf("%w: HCL report is %d bytes, need at least %d", ErrInvalidReport, len(raw), end)
			}
			return raw[headerSize:end], nil
		}
	}

	return nil, fmt.Errorf("%w: SEV-SNP report is %d bytes, expected %d", ErrInvalidReport, len(raw), SNPReportSize)
}
