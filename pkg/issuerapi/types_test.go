package issuerapi

import (
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

// These tests lock the JSON wire format. If a json tag changes, these fail.

const testCertPEM = `-----BEGIN CERTIFICATE-----
dGVzdA==
-----END CERTIFICATE-----
`

const testCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
dGVzdA==
-----END CERTIFICATE REQUEST-----
`

func TestSignCSRRequestWireFormat(t *testing.T) {
	raw := `{"ear":"token","csr":"` + jsonEscape(testCSRPEM) + `","ttl":"24h"}`

	var req SignCSRRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.EAR != "token" {
		t.Errorf("EAR = %q, want %q", req.EAR, "token")
	}
	if req.CSR.BlockType() != "CERTIFICATE REQUEST" {
		t.Errorf("CSR.BlockType() = %q, want %q", req.CSR.BlockType(), "CERTIFICATE REQUEST")
	}
	if req.TTL.Duration != 24*time.Hour {
		t.Errorf("TTL = %v, want %v", req.TTL.Duration, 24*time.Hour)
	}

	// Round-trip: marshal and verify field names.
	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	for _, key := range []string{"ear", "csr", "ttl"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
	if len(m) != 3 {
		t.Errorf("got %d JSON fields, want 3", len(m))
	}
}

func TestSignCSRResponseWireFormat(t *testing.T) {
	raw := `{"certificate":"` + jsonEscape(testCertPEM) + `","ca_certificate":"` + jsonEscape(testCertPEM) + `"}`

	var resp SignCSRResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Certificate.BlockType() != "CERTIFICATE" {
		t.Errorf("Certificate.BlockType() = %q, want %q", resp.Certificate.BlockType(), "CERTIFICATE")
	}
	if resp.CACertificate.BlockType() != "CERTIFICATE" {
		t.Errorf("CACertificate.BlockType() = %q, want %q", resp.CACertificate.BlockType(), "CERTIFICATE")
	}

	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	for _, key := range []string{"certificate", "ca_certificate"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
	if len(m) != 2 {
		t.Errorf("got %d JSON fields, want 2", len(m))
	}
}

func TestPEMDataInvalidRejectsOnUnmarshal(t *testing.T) {
	raw := `{"ear":"x","csr":"not-pem-data","ttl":"1h"}`
	var req SignCSRRequest
	if err := json.Unmarshal([]byte(raw), &req); err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestPEMDataEmptyAllowed(t *testing.T) {
	raw := `{"ear":"x","csr":"","ttl":""}`
	var req SignCSRRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.CSR.DER() != nil {
		t.Error("expected nil DER for empty PEM")
	}
	if req.TTL.Duration != 0 {
		t.Errorf("expected zero duration, got %v", req.TTL.Duration)
	}
}

func TestDurationNegativeRejectsOnUnmarshal(t *testing.T) {
	raw := `{"ear":"x","csr":"","ttl":"-1h"}`
	var req SignCSRRequest
	if err := json.Unmarshal([]byte(raw), &req); err == nil {
		t.Error("expected error for negative duration, got nil")
	}
}

func TestDurationZeroRejectsOnUnmarshal(t *testing.T) {
	raw := `{"ear":"x","csr":"","ttl":"0s"}`
	var req SignCSRRequest
	if err := json.Unmarshal([]byte(raw), &req); err == nil {
		t.Error("expected error for zero duration, got nil")
	}
}

func TestDurationInvalidRejectsOnUnmarshal(t *testing.T) {
	raw := `{"ear":"x","csr":"","ttl":"bogus"}`
	var req SignCSRRequest
	if err := json.Unmarshal([]byte(raw), &req); err == nil {
		t.Error("expected error for invalid duration, got nil")
	}
}

func TestPEMDataRoundTrip(t *testing.T) {
	p := NewPEMDataFromDER("CERTIFICATE", []byte("test"))
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var p2 PEMData
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(p2.DER()) != "test" {
		t.Errorf("DER = %q, want %q", p2.DER(), "test")
	}
	if p2.BlockType() != "CERTIFICATE" {
		t.Errorf("BlockType = %q, want %q", p2.BlockType(), "CERTIFICATE")
	}
}

func TestPEMDataMultipleBlocks(t *testing.T) {
	multi := testCertPEM + testCertPEM
	p, err := NewPEMData([]byte(multi))
	if err != nil {
		t.Fatalf("NewPEMData: %v", err)
	}
	if len(p.Blocks()) != 2 {
		t.Errorf("got %d blocks, want 2", len(p.Blocks()))
	}
	all := p.DERAll()
	if len(all) != 2 {
		t.Errorf("DERAll returned %d entries, want 2", len(all))
	}
	if string(all[0]) != "test" || string(all[1]) != "test" {
		t.Errorf("DERAll content mismatch")
	}
}

func TestDurationRoundTrip(t *testing.T) {
	d := Duration{Duration: 2*time.Hour + 30*time.Minute}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var d2 Duration
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d2.Duration != d.Duration {
		t.Errorf("got %v, want %v", d2.Duration, d.Duration)
	}
}

// jsonEscape encodes a string for embedding in JSON.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	// Strip surrounding quotes.
	return string(b[1 : len(b)-1])
}

func TestNewPEMData(t *testing.T) {
	p, err := NewPEMData([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("NewPEMData: %v", err)
	}
	if p.BlockType() != "CERTIFICATE" {
		t.Errorf("BlockType = %q, want %q", p.BlockType(), "CERTIFICATE")
	}

	_, err = NewPEMData([]byte("not pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestNewPEMDataFromDER(t *testing.T) {
	p := NewPEMDataFromDER("CERTIFICATE REQUEST", []byte("der-bytes"))
	if p.BlockType() != "CERTIFICATE REQUEST" {
		t.Errorf("BlockType = %q, want %q", p.BlockType(), "CERTIFICATE REQUEST")
	}
	if string(p.DER()) != "der-bytes" {
		t.Errorf("DER = %q, want %q", p.DER(), "der-bytes")
	}

	// Verify it round-trips through PEM decode.
	block, _ := pem.Decode(p.Bytes())
	if block == nil {
		t.Fatal("expected valid PEM from NewPEMDataFromDER")
	}
	if string(block.Bytes) != "der-bytes" {
		t.Errorf("re-decoded DER = %q, want %q", block.Bytes, "der-bytes")
	}
}
