package ratls

import (
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// The RA-TLS extension, its wire format and its verification live in
// attestation-go/ratls. What follows is the c8s spelling of that surface, kept
// because the call sites are many and the names are load-bearing in the docs;
// new code can take the library names directly.

// Attestation is the TEE evidence an RA-TLS certificate extension carries.
type Attestation = agratls.Attestation

// TEEType is the hardware family recorded in the extension.
type TEEType = agratls.TEEType

const (
	// TEETypeSEVSNP is AMD SEV-SNP: snp, az-snp, gcp-snp.
	TEETypeSEVSNP = agratls.TEETypeSEVSNP
	// TEETypeTDX is Intel TDX: tdx, az-tdx, gcp-tdx.
	TEETypeTDX = agratls.TEETypeTDX

	// SNPReportSize is the exact size of an AMD SEV-SNP attestation report
	// (ATTESTATION_REPORT, AMD SEV-SNP ABI Specification).
	SNPReportSize = agratls.SNPReportSize

	// SNPMeasurementSize is the size of an SEV-SNP launch measurement
	// (SHA-384 digest = 48 bytes).
	SNPMeasurementSize = runtimemeasure.Size
)

// OIDRATLSAttestation identifies the RA-TLS attestation extension, under the
// 1.3.6.1.4.1.66378 arc (our Private Enterprise Number):
//
//	1.3.6.1.4.1.66378.1   - confidential TEE attestation arc
//	1.3.6.1.4.1.66378.1.1 - RA-TLS attestation extension (attestation-go/ratls)
//	1.3.6.1.4.1.66378.1.2 - attestation-evidence audit digest (certutil)
//	1.3.6.1.4.1.66378.1.4 - pod sandbox ID extension (sandbox.go)
//	1.3.6.1.4.1.66378.1.5 - matched workload extension (matchedworkload.go)
//
// .1.3 was the RA-TLS config-claims extension; it is retired, not reusable.
var OIDRATLSAttestation = agratls.OIDRATLSAttestation

var (
	// ReportDataForKey computes the REPORTDATA binding a public key (and an
	// optional nonce) to a TEE report: SHA-384, zero-padded to 64 bytes.
	ReportDataForKey = agratls.ReportDataForKey

	// UnmarshalExtension decodes a DER-encoded attestation extension.
	UnmarshalExtension = agratls.UnmarshalExtension

	// ExtractAttestation parses the RA-TLS extension out of a certificate.
	ExtractAttestation = agratls.ExtractAttestation

	// NormalizeSEVSNPReport returns the raw AMD report, unwrapping the Hyper-V
	// HCL envelope an Azure guest's vTPM puts around it.
	NormalizeSEVSNPReport = agratls.NormalizeSEVSNPReport
)
