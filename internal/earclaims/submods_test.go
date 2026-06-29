package earclaims

import (
	"encoding/json"
	"testing"
)

func TestLaunchDigestFromSubmodsSuccess(t *testing.T) {
	raw := json.RawMessage(`{"attester":{"launch_digest":"abc123"}}`)
	got, err := LaunchDigestFromSubmods(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc123" {
		t.Errorf("got %q, want abc123", got)
	}
}

func TestLaunchDigestFromSubmodsMissingAttester(t *testing.T) {
	raw := json.RawMessage(`{"other":{"launch_digest":"abc"}}`)
	_, err := LaunchDigestFromSubmods(raw)
	if err == nil {
		t.Fatal("expected error for missing attester")
	}
	if !contains(err.Error(), SubmodAttester) {
		t.Errorf("error %q should mention attester", err.Error())
	}
}

func TestLaunchDigestFromSubmodsMissingLaunchDigest(t *testing.T) {
	raw := json.RawMessage(`{"attester":{"other":"x"}}`)
	_, err := LaunchDigestFromSubmods(raw)
	if err == nil {
		t.Fatal("expected error for missing launch_digest")
	}
	if !contains(err.Error(), LaunchDigest) {
		t.Errorf("error %q should mention launch_digest", err.Error())
	}
}

func TestLaunchDigestFromSubmodsEmptyLaunchDigest(t *testing.T) {
	raw := json.RawMessage(`{"attester":{"launch_digest":""}}`)
	_, err := LaunchDigestFromSubmods(raw)
	if err == nil {
		t.Fatal("expected error for empty launch_digest")
	}
}

func TestLaunchDigestFromSubmodsInvalidSubmodsJSON(t *testing.T) {
	_, err := LaunchDigestFromSubmods(json.RawMessage(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid submods JSON")
	}
}

func TestLaunchDigestFromSubmodsInvalidAttesterJSON(t *testing.T) {
	// attester present but launch_digest claim has wrong type.
	raw := json.RawMessage(`{"attester":{"launch_digest":123}}`)
	_, err := LaunchDigestFromSubmods(raw)
	if err == nil {
		t.Fatal("expected error for non-string launch_digest")
	}
}
