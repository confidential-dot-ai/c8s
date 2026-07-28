package attestclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestTEETypeForPlatform(t *testing.T) {
	cases := map[string]struct {
		want    ratls.TEEType
		wantErr bool
	}{
		"snp":     {ratls.TEETypeSEVSNP, false},
		"az-snp":  {ratls.TEETypeSEVSNP, false},
		"gcp-snp": {ratls.TEETypeSEVSNP, false},
		"tdx":     {ratls.TEETypeTDX, false},
		"az-tdx":  {ratls.TEETypeTDX, false},
		"auto":    {0, true},
		"":        {0, true},
	}
	for platform, tc := range cases {
		got, err := TEETypeForPlatform(platform)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%q: err = %v, wantErr %t", platform, err, tc.wantErr)
		}
		if got != tc.want {
			t.Fatalf("%q: TEEType = %d, want %d", platform, got, tc.want)
		}
	}
}

// attestSpy is an attestation-api /attest stub that records the report_data it
// was asked to bind and returns a well-formed (all-zero) SNP report.
func attestSpy(t *testing.T, gotReportData *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		var req types.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode attest request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*gotReportData = req.ReportData.Bytes()
		report := base64.StdEncoding.EncodeToString(make([]byte, ratls.SNPReportSize))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": json.RawMessage(`{"attestation_report":"` + report + `"}`),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAttestationExtensionForClaims_BindsFoldedClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := &ratls.ConfigClaims{
		OperatorKeysDigest: ratls.UnsetDigest(),
		SeedDigest:         ratls.UnsetDigest(),
		WorkloadDigest:     make([]byte, ratls.ClaimsDigestSize),
	}
	claims.WorkloadDigest[0] = 0xAB
	claimsExt, err := claims.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}

	var sentReportData []byte
	srv := attestSpy(t, &sentReportData)

	ext, err := NewClient("").AttestationExtensionForClaims(context.Background(), srv.URL, &key.PublicKey, claimsExt.Value)
	if err != nil {
		t.Fatalf("AttestationExtensionForClaims: %v", err)
	}
	if !ext.Id.Equal(ratls.OIDRATLSAttestation) {
		t.Fatalf("extension OID = %v, want %v", ext.Id, ratls.OIDRATLSAttestation)
	}

	// The evidence must be bound to the nonce-free anchor over the same claims
	// the leaf will carry — that equality is what makes the leaf verifiable.
	want, err := ratls.ReportDataForKeyAndClaims(&key.PublicKey, claimsExt.Value, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(sentReportData) != string(want[:sha512.Size384]) {
		t.Fatalf("bound report data = %x, want folded anchor %x", sentReportData, want[:sha512.Size384])
	}

	att, err := ratls.UnmarshalExtension(ext.Value)
	if err != nil {
		t.Fatalf("extension does not parse as an attestation: %v", err)
	}
	if att.TEEType != ratls.TEETypeSEVSNP {
		t.Fatalf("TEEType = %d, want SEV-SNP", att.TEEType)
	}
}

func TestAttestationExtensionForClaims_NilClaimsBindsKeyOnly(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var sentReportData []byte
	srv := attestSpy(t, &sentReportData)

	if _, err := NewClient("").AttestationExtensionForClaims(context.Background(), srv.URL, &key.PublicKey, nil); err != nil {
		t.Fatalf("AttestationExtensionForClaims: %v", err)
	}
	want, err := ratls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(sentReportData) != string(want[:sha512.Size384]) {
		t.Fatalf("nil claims: bound report data = %x, want plain key anchor %x", sentReportData, want[:sha512.Size384])
	}
}

// TestRATLSEvidenceTDXStripsEventlog: bare-metal TDX evidence must be embedded
// as the envelope with cc_eventlog dropped and the quote kept.
func TestRATLSEvidenceTDXStripsEventlog(t *testing.T) {
	resp := types.AttestResponse{
		Platform: string(types.PlatformTdx),
		Evidence: json.RawMessage(`{"quote":"abc","cc_eventlog":"AAAA"}`),
	}
	out, err := RATLSEvidence(resp)
	if err != nil {
		t.Fatalf("RATLSEvidence: %v", err)
	}
	var envelope struct {
		Platform string                     `json:"platform"`
		Evidence map[string]json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("unmarshal envelope %q: %v", out, err)
	}
	if envelope.Platform != string(types.PlatformTdx) {
		t.Errorf("platform = %q, want tdx", envelope.Platform)
	}
	if got := string(envelope.Evidence["quote"]); got != `"abc"` {
		t.Errorf("quote = %s, want \"abc\"", got)
	}
	if _, ok := envelope.Evidence["cc_eventlog"]; ok {
		t.Error("cc_eventlog survived the strip")
	}
	if len(envelope.Evidence) != 1 {
		t.Errorf("evidence keys = %d, want only quote", len(envelope.Evidence))
	}
}

func TestRATLSEvidenceTDXBadEvidence(t *testing.T) {
	resp := types.AttestResponse{
		Platform: string(types.PlatformTdx),
		Evidence: json.RawMessage(`not-json`),
	}
	if _, err := RATLSEvidence(resp); err == nil {
		t.Fatal("expected error for unparseable tdx evidence")
	}
}
