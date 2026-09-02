package attestclient_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hclEnvelope builds an AKS HCL envelope wrapping the given hardware report:
// header(32) + report + var_data header(20) + var_data content, with trailing
// null padding bytes after the content.
func hclEnvelope(report []byte, trailing int) []byte {
	varData := []byte(`{"keys":[]}`)
	env := make([]byte, 32+len(report)+20+len(varData)+trailing)
	copy(env[:4], "HCLA")
	copy(env[32:], report)
	hdr := env[32+len(report):]
	binary.LittleEndian.PutUint32(hdr[8:12], 2) // report_type: SNP
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(varData)+trailing))
	copy(hdr[20:], varData)
	return env
}

func TestExtractSNPReport_BareMetal(t *testing.T) {
	// Bare-metal SNP: attestation_report field, standard base64.
	fakeReport := make([]byte, 1184)
	fakeReport[0] = 0x02 // SNP version marker
	evidence := map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(fakeReport),
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "snp",
		Evidence: evidenceJSON,
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport failed: %v", err)
	}
	if len(report) != 1184 {
		t.Errorf("report length = %d, want 1184", len(report))
	}
	if report[0] != 0x02 {
		t.Errorf("report[0] = %02x, want 0x02", report[0])
	}
}

func TestExtractSNPReport_VTPM(t *testing.T) {
	// vTPM (az-snp): hcl_report field, URL-safe base64 (no padding).
	fakeHCLReport := make([]byte, 1184)
	fakeHCLReport[0] = 0x02
	evidence := map[string]any{
		"version":    1,
		"hcl_report": base64.RawURLEncoding.EncodeToString(fakeHCLReport),
		"tpm_quote": map[string]any{
			"signature": "deadbeef",
			"message":   "cafebabe",
			"pcrs":      []string{},
		},
		"vcek": "fake-vcek",
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "az-snp",
		Evidence: evidenceJSON,
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport failed: %v", err)
	}
	if len(report) != 1184 {
		t.Errorf("report length = %d, want 1184", len(report))
	}
}

func TestRATLSEvidence_VTPMPreservesEnvelope(t *testing.T) {
	fakeHCLReport := hclEnvelope(make([]byte, 1184), 64)
	evidence := map[string]any{
		"version":    1,
		"hcl_report": base64.RawURLEncoding.EncodeToString(fakeHCLReport),
		"tpm_quote": map[string]any{
			"signature": "deadbeef",
			"message":   "cafebabe",
			"pcrs":      []string{},
		},
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{Platform: "az-snp", Evidence: evidenceJSON}
	payload, err := attestclient.RATLSEvidence(resp)
	if err != nil {
		t.Fatalf("RATLSEvidence failed: %v", err)
	}

	var embedded types.AttestationEvidence
	if err := json.Unmarshal([]byte(payload), &embedded); err != nil {
		t.Fatalf("embedded evidence is not JSON: %v", err)
	}
	if embedded.Platform != "az-snp" {
		t.Fatalf("embedded platform = %q, want az-snp", embedded.Platform)
	}
	if !bytes.Equal(embedded.Evidence, evidenceJSON) {
		t.Fatal("embedded evidence was not preserved")
	}
}

func TestExtractSNPReport_HCLEnvelope(t *testing.T) {
	fakeReport := make([]byte, 1184)
	fakeReport[0] = 0x03
	fakeReport[64] = 0x99
	hclReport := hclEnvelope(fakeReport, 128)
	evidence := map[string]any{
		"hcl_report": base64.RawURLEncoding.EncodeToString(hclReport),
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "az-snp",
		Evidence: evidenceJSON,
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport failed: %v", err)
	}
	if !bytes.Equal([]byte(report), fakeReport) {
		t.Fatalf("report mismatch after HCL unwrap")
	}
}

func TestExtractSNPReport_HCLTooShort(t *testing.T) {
	// HCLA signature is present, but the buffer is shorter than header + SNP report.
	short := make([]byte, 32+1184-1)
	copy(short[:4], "HCLA")
	evidence := map[string]any{
		"hcl_report": base64.RawURLEncoding.EncodeToString(short),
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "az-snp",
		Evidence: evidenceJSON,
	}

	if _, err := attestclient.ExtractSNPReport(resp); err == nil {
		t.Fatal("expected error for truncated HCL envelope")
	}
}

func TestExtractSNPReport_HCLMissingSignature(t *testing.T) {
	// 1216-byte buffer (header + SNP report) that does not start with HCLA.
	buf := make([]byte, 32+1184)
	copy(buf[:4], "XXXX")
	evidence := map[string]any{
		"hcl_report": base64.RawURLEncoding.EncodeToString(buf),
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "az-snp",
		Evidence: evidenceJSON,
	}

	if _, err := attestclient.ExtractSNPReport(resp); err == nil {
		t.Fatal("expected error for missing HCLA signature")
	}
}

// TestExtractSNPReport_RealAKSEnvelope anchors the HCL parser to a captured
// AKS az-snp evidence dump. Regenerate testdata/aks_hcl_envelope.bin from a
// live `hcl_report` with a URL-safe base64 decoder, for example
// `python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.urlsafe_b64decode(sys.stdin.read().strip()+"=="))'`
// — NOT `base64 -d`, whose standard alphabet silently drops the `-`/`_`
// characters and corrupts the report (that mangled an earlier fixture).
func TestExtractSNPReport_RealAKSEnvelope(t *testing.T) {
	envelope, err := os.ReadFile("testdata/aks_hcl_envelope.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	evidence := map[string]any{
		"hcl_report": base64.RawURLEncoding.EncodeToString(envelope),
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "az-snp",
		Evidence: evidenceJSON,
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport on real AKS envelope: %v", err)
	}
	if len(report) != ratls.SNPReportSize {
		t.Fatalf("report length = %d, want %d", len(report), ratls.SNPReportSize)
	}
	// First 4 bytes of an AMD SEV-SNP report are the version field (uint32 LE).
	// Currently shipping versions are 2 and 3; reject anything else as a
	// sanity check that we sliced the right bytes.
	version := binary.LittleEndian.Uint32([]byte(report[:4]))
	if version != 2 && version != 3 {
		t.Fatalf("SNP report version = %d, want 2 or 3", version)
	}
}

func TestExtractSNPReport_NoReport(t *testing.T) {
	evidence := map[string]string{"something_else": "value"}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "unknown",
		Evidence: evidenceJSON,
	}

	_, err := attestclient.ExtractSNPReport(resp)
	if err == nil {
		t.Fatal("expected error for missing report fields")
	}
}
