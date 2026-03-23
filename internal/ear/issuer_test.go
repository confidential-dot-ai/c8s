package ear

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

func TestIssuesValid3PartJWT(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{"foo":"bar"}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	for i, part := range parts {
		if len(part) == 0 {
			t.Fatalf("part %d is empty", i)
		}
	}
}

func TestTokenContainsRequiredEARClaims(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{"evidence":"data"}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	requiredKeys := []string{"eat_profile", "iss", "iat", "exp", "submods", "ear_verifier_id"}
	for _, key := range requiredKeys {
		if _, ok := claims[key]; !ok {
			t.Fatalf("missing required claim: %s", key)
		}
	}

	var eatProfile string
	if err := json.Unmarshal(claims["eat_profile"], &eatProfile); err != nil {
		t.Fatalf("unmarshal eat_profile: %v", err)
	}
	if eatProfile != "tag:ietf.org,2026:rats/ear#03" {
		t.Fatalf("eat_profile: got %q, want %q", eatProfile, "tag:ietf.org,2026:rats/ear#03")
	}

	var iss string
	if err := json.Unmarshal(claims["iss"], &iss); err != nil {
		t.Fatalf("unmarshal iss: %v", err)
	}
	if iss != "test-issuer" {
		t.Fatalf("iss: got %q, want %q", iss, "test-issuer")
	}
}

func TestTokenExpiryMatchesLifetime(t *testing.T) {
	keyPEM := testKeyPEM(t)
	lifetime := 10 * time.Minute
	issuer, err := NewIssuer(keyPEM, "test-issuer", lifetime)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims struct {
		Iat float64 `json:"iat"`
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	diff := claims.Exp - claims.Iat
	expected := lifetime.Seconds()
	if diff != expected {
		t.Fatalf("exp - iat = %v, want %v", diff, expected)
	}
}

func TestRejectsInvalidKey(t *testing.T) {
	_, err := NewIssuer([]byte("not a pem key"), "test-issuer", 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}
