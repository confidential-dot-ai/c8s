package types

import (
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
		Evidence: AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{}`),
		},
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

	if _, ok := raw["params"]; ok {
		t.Fatal("params should be omitted when nil")
	}
	if _, ok := raw["issue_token"]; ok {
		t.Fatal("issue_token should be omitted when nil")
	}

	// Now with values set
	req2 := VerifyRequest{
		Evidence: AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{}`),
		},
		Params: &VerifyParams{
			AllowDebug: new(bool),
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
