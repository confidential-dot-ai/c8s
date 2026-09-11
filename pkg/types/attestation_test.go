package types

import (
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

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
		Evidence: teetypes.AttestationEvidence{
			Platform: teetypes.PlatformSNP,
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
	if decoded.Evidence.Platform != teetypes.PlatformSNP {
		t.Fatalf("platform: got %q, want %q", decoded.Evidence.Platform, teetypes.PlatformSNP)
	}
	if string(decoded.Evidence.Evidence) != `{"key":"value"}` {
		t.Fatalf("evidence: got %s, want %s", decoded.Evidence.Evidence, `{"key":"value"}`)
	}
	if decoded.CSR != "csr-data" {
		t.Fatalf("csr: got %q, want %q", decoded.CSR, "csr-data")
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
