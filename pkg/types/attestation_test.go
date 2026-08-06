package types

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func ptrTo[T any](v T) *T { return &v }

func TestBase64BytesJSONRoundtrip(t *testing.T) {
	original := NewBase64Bytes([]byte("hello world"))

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Should be a base64-encoded string in JSON
	if string(data) != `"aGVsbG8gd29ybGQ="` {
		t.Fatalf("unexpected marshal output: %s", data)
	}

	var decoded Base64Bytes
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if string(decoded.Bytes()) != "hello world" {
		t.Fatalf("got %q, want %q", decoded.Bytes(), "hello world")
	}
}

func TestChallengeResponseJSONRoundtrip(t *testing.T) {
	resp := ChallengeResponse{Challenge: "abc123"}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded ChallengeResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Challenge != "abc123" {
		t.Fatalf("got %q, want %q", decoded.Challenge, "abc123")
	}
}

func TestAttestRequestBodyJSONRoundtrip(t *testing.T) {
	req := AttestRequestBody{
		Challenge: "challenge-value",
		Evidence: AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{"key":"value"}`),
		},
		CSR: "csr-data",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded AttestRequestBody
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Challenge != "challenge-value" {
		t.Fatalf("challenge: got %q, want %q", decoded.Challenge, "challenge-value")
	}
	if decoded.Evidence.Platform != "snp" {
		t.Fatalf("platform: got %q, want %q", decoded.Evidence.Platform, "snp")
	}
	if string(decoded.Evidence.Evidence) != `{"key":"value"}` {
		t.Fatalf("evidence: got %s, want %s", decoded.Evidence.Evidence, `{"key":"value"}`)
	}
	if decoded.CSR != "csr-data" {
		t.Fatalf("csr: got %q, want %q", decoded.CSR, "csr-data")
	}
}

func TestVerifyRequestOmitemptyFields(t *testing.T) {
	req := VerifyRequest{
		Platform: "snp",
		Evidence: json.RawMessage(`{}`),
		// Params and IssueToken are nil - should be omitted
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// platform must be at the top level (not nested under evidence).
	if string(raw["platform"]) != `"snp"` {
		t.Fatalf("top-level platform = %s, want \"snp\"", raw["platform"])
	}
	if _, ok := raw["params"]; ok {
		t.Fatal("params should be omitted when nil")
	}
	if _, ok := raw["issue_token"]; ok {
		t.Fatal("issue_token should be omitted when nil")
	}

	// Now with values set
	req2 := VerifyRequest{
		Platform: "snp",
		Evidence: json.RawMessage(`{}`),
		Params: &VerifyParams{
			AllowDebug: ptrTo(false),
		},
		IssueToken: ptrTo(true),
	}

	data2, err := json.Marshal(req2)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw2 map[string]json.RawMessage
	if err := json.Unmarshal(data2, &raw2); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	if _, ok := raw2["params"]; !ok {
		t.Fatal("params should be present when set")
	}
	if _, ok := raw2["issue_token"]; !ok {
		t.Fatal("issue_token should be present when set")
	}
}

func TestErrorResponseJSONRoundtrip(t *testing.T) {
	resp := ErrorResponse{
		Error:   "not_found",
		Message: "resource not found",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Error != "not_found" {
		t.Fatalf("error: got %q, want %q", decoded.Error, "not_found")
	}
	if decoded.Message != "resource not found" {
		t.Fatalf("message: got %q, want %q", decoded.Message, "resource not found")
	}
}

func TestVerifyReportData(t *testing.T) {
	evidence := AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"q":1}`)}
	reportData := NewBase64Bytes([]byte("report-data-digest"))

	req := VerifyReportData(evidence, reportData)

	// VerifyReportData must split the envelope into the top-level platform +
	// platform-specific evidence shape attestation-api's /verify expects.
	if req.Platform != "snp" {
		t.Fatalf("platform = %q, want snp", req.Platform)
	}
	if string(req.Evidence) != `{"q":1}` {
		t.Fatalf("evidence = %s, want the inner platform-specific evidence", req.Evidence)
	}
	if req.Params == nil || req.Params.ExpectedReportData == nil {
		t.Fatalf("expected report-data binding, got params=%+v", req.Params)
	}
	if got := req.Params.ExpectedReportData.Bytes(); !bytes.Equal(got, reportData.Bytes()) {
		t.Fatalf("expected report-data = %x, want %x", got, reportData.Bytes())
	}
	// Token issuance must be explicitly off — c8s mints its own EAR.
	if req.IssueToken == nil || *req.IssueToken {
		t.Fatalf("IssueToken = %v, want explicit false", req.IssueToken)
	}
}

func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSignCsrResponseSignedCert(t *testing.T) {
	leaf := selfSignedCertPEM(t)
	ca := selfSignedCertPEM(t)
	leafTrim := strings.TrimSpace(leaf)
	caTrim := strings.TrimSpace(ca)

	cases := map[string]struct {
		resp    SignCsrResponse
		want    string
		wantErr string
	}{
		"leaf only": {
			resp: SignCsrResponse{Certificate: leaf},
			want: leafTrim + "\n",
		},
		"leaf plus ca bundle": {
			resp: SignCsrResponse{Certificate: leaf, CACertificate: ca},
			want: leafTrim + "\n" + caTrim + "\n",
		},
		"empty certificate": {
			resp:    SignCsrResponse{CACertificate: ca},
			wantErr: "certificate is required",
		},
		"whitespace certificate": {
			resp:    SignCsrResponse{Certificate: "  \n\t"},
			wantErr: "certificate is required",
		},
		"non-PEM certificate": {
			resp:    SignCsrResponse{Certificate: "not a certificate"},
			wantErr: "PEM-encoded X.509",
		},
		"two leaf blocks": {
			resp:    SignCsrResponse{Certificate: leaf + selfSignedCertPEM(t)},
			wantErr: "exactly one CERTIFICATE block",
		},
		"garbage ca": {
			resp:    SignCsrResponse{Certificate: leaf, CACertificate: "not a ca"},
			wantErr: "ca_certificate must be PEM-encoded X.509",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tc.resp.SignedCert()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("SignedCert: %v", err)
			}
			if got != tc.want {
				t.Fatalf("SignedCert = %q, want %q", got, tc.want)
			}
		})
	}
}
