package types

import (
	"bytes"
	"encoding/json"
	"testing"
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
