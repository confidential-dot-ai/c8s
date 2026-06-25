package verify

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func discoveryDocWith(t *testing.T, certPEM string, challenge []byte, evidence string) []byte {
	t.Helper()
	doc := map[string]any{
		"cds_tls": map[string]any{"certificate_pem": certPEM},
		"attestation": map[string]any{
			"challenge": base64.StdEncoding.EncodeToString(challenge),
			"platform":  "snp",
			"evidence":  json.RawMessage(evidence),
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery doc: %v", err)
	}
	return data
}

func TestEvidenceFromAttestation(t *testing.T) {
	t.Run("snp raw report wraps as attestation_report, omits empty cert_chain", func(t *testing.T) {
		platform, raw, err := evidenceFromAttestation(&ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: []byte{9}})
		if err != nil {
			t.Fatal(err)
		}
		if platform != "snp" {
			t.Errorf("platform = %q, want snp", platform)
		}
		var inner map[string]any
		_ = json.Unmarshal(raw, &inner)
		if inner["attestation_report"] != base64.StdEncoding.EncodeToString([]byte{9}) {
			t.Errorf("attestation_report = %v", inner["attestation_report"])
		}
		// No VCEK in the cert → the verifier fetches it from KDS, so omit cert_chain.
		if _, ok := inner["cert_chain"]; ok {
			t.Errorf("bare report must omit cert_chain, got %v", inner)
		}
	})

	t.Run("snp with cert chain includes vcek", func(t *testing.T) {
		_, raw, err := evidenceFromAttestation(&ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: []byte{1}, CertChain: []byte{4, 5}})
		if err != nil {
			t.Fatal(err)
		}
		var inner map[string]any
		_ = json.Unmarshal(raw, &inner)
		cc, _ := inner["cert_chain"].(map[string]any)
		if cc == nil || cc["vcek"] != base64.StdEncoding.EncodeToString([]byte{4, 5}) {
			t.Errorf("cert_chain.vcek missing/wrong: %v", inner["cert_chain"])
		}
	})

	t.Run("raw TDX report is rejected (use discovery/endpoint)", func(t *testing.T) {
		if _, _, err := evidenceFromAttestation(&ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: []byte{1}}); err == nil {
			t.Fatal("expected a raw TDX report from a cert to be rejected")
		}
	})
}
