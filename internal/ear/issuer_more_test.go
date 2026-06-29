package ear

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/pkg/jwks"
)

func decodeJWTHeader(t *testing.T, token string, v any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if err := json.Unmarshal(header, v); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
}

func TestKidMatchesThumbprint(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	pub := issuer.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}
	want, err := jwks.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got := issuer.Kid(); got != want {
		t.Fatalf("Kid() = %q, want %q", got, want)
	}
}

func TestKidMatchesTokenHeader(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var header map[string]any
	decodeJWTHeader(t, token, &header)
	if header["kid"] != issuer.Kid() {
		t.Fatalf("header kid = %v, want %q", header["kid"], issuer.Kid())
	}
}

func TestZeroValueIssuerAccessors(t *testing.T) {
	var iss Issuer
	if pub := iss.PublicKey(); pub != nil {
		t.Fatalf("PublicKey() = %v, want nil for zero Issuer", pub)
	}
	if kid := iss.Kid(); kid != "" {
		t.Fatalf("Kid() = %q, want empty for zero Issuer", kid)
	}
}

func TestPublicKeyNilWhenMatUnset(t *testing.T) {
	keyPEM := testKeyPEM(t)
	iss, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	// Clear the stored key material to exercise the nil-load branches.
	iss.mat.Store(nil)

	if pub := iss.PublicKey(); pub != nil {
		t.Fatalf("PublicKey() = %v, want nil after clearing key", pub)
	}
	if kid := iss.Kid(); kid != "" {
		t.Fatalf("Kid() = %q, want empty after clearing key", kid)
	}
	if _, err := iss.Issue(json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error issuing with no signing key configured")
	}
}

func TestPublicKeyIsCopy(t *testing.T) {
	keyPEM := testKeyPEM(t)
	iss, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	a := iss.PublicKey()
	b := iss.PublicKey()
	if a == b {
		t.Fatal("PublicKey returned the same pointer; expected a copy")
	}
	if !a.Equal(b) {
		t.Fatal("PublicKey copies are not equal")
	}
}

func TestSwapKeyRotatesSigningMaterial(t *testing.T) {
	keyPEM := testKeyPEM(t)
	iss, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	origKid := iss.Kid()

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	newKid, err := jwks.Thumbprint(&newKey.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	// A value copy must observe the swap through the shared atomic pointer.
	copyIss := iss
	iss.SwapKey(newKey, newKid)

	if copyIss.Kid() != newKid {
		t.Fatalf("copy Kid() = %q, want rotated %q", copyIss.Kid(), newKid)
	}
	if copyIss.Kid() == origKid {
		t.Fatal("copy still reports the original kid after swap")
	}
	if !copyIss.PublicKey().Equal(&newKey.PublicKey) {
		t.Fatal("copy PublicKey() did not reflect the swapped key")
	}

	token, err := copyIss.Issue(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("issue after swap: %v", err)
	}
	var header map[string]any
	decodeJWTHeader(t, token, &header)
	if header["kid"] != newKid {
		t.Fatalf("token kid = %v, want rotated %q", header["kid"], newKid)
	}
}

func TestIssueForRequestBodySetsPayloadBodyHash(t *testing.T) {
	keyPEM := testKeyPEM(t)
	iss, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	body := []byte(`{"request":"payload"}`)
	token, err := iss.IssueForRequestBody(json.RawMessage(`{"evidence":"data"}`), "digest123", body)
	if err != nil {
		t.Fatalf("issue for request body: %v", err)
	}

	var claims map[string]json.RawMessage
	decodeJWTPayload(t, token, &claims)

	var pbh string
	if err := json.Unmarshal(claims[earclaims.PayloadBodyHash], &pbh); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.PayloadBodyHash, err)
	}
	sum := sha256.Sum256(body)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if pbh != want {
		t.Fatalf("%s = %q, want %q", earclaims.PayloadBodyHash, pbh, want)
	}

	// The launch digest passed through should also be present.
	var submods map[string]json.RawMessage
	if err := json.Unmarshal(claims[earclaims.Submods], &submods); err != nil {
		t.Fatalf("unmarshal submods: %v", err)
	}
	var attester map[string]json.RawMessage
	if err := json.Unmarshal(submods[earclaims.SubmodAttester], &attester); err != nil {
		t.Fatalf("unmarshal attester: %v", err)
	}
	var ld string
	if err := json.Unmarshal(attester[earclaims.LaunchDigest], &ld); err != nil {
		t.Fatalf("unmarshal launch digest: %v", err)
	}
	if ld != "digest123" {
		t.Fatalf("launch digest = %q, want digest123", ld)
	}
}

func TestIssueOmitsOptionalClaimsWhenEmpty(t *testing.T) {
	keyPEM := testKeyPEM(t)
	iss, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := iss.Issue(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var claims map[string]json.RawMessage
	decodeJWTPayload(t, token, &claims)

	if _, ok := claims[earclaims.TEEPublicKey]; ok {
		t.Fatalf("did not expect %s claim when no TEE key given", earclaims.TEEPublicKey)
	}
	if _, ok := claims[earclaims.PayloadBodyHash]; ok {
		t.Fatalf("did not expect %s claim with no request body", earclaims.PayloadBodyHash)
	}

	var submods map[string]json.RawMessage
	if err := json.Unmarshal(claims[earclaims.Submods], &submods); err != nil {
		t.Fatalf("unmarshal submods: %v", err)
	}
	var attester map[string]json.RawMessage
	if err := json.Unmarshal(submods[earclaims.SubmodAttester], &attester); err != nil {
		t.Fatalf("unmarshal attester: %v", err)
	}
	if _, ok := attester[earclaims.LaunchDigest]; ok {
		t.Fatalf("did not expect %s when launch digest empty", earclaims.LaunchDigest)
	}

	// Status should be the affirming tier.
	var status int
	if err := json.Unmarshal(attester[earclaims.EARStatus], &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if status != statusAffirming {
		t.Fatalf("status = %d, want %d", status, statusAffirming)
	}
}

func TestNewIssuerRejectsNonECKey(t *testing.T) {
	// An RSA key is not an EC private key and must be rejected by NewIssuer.
	rsaPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not-a-real-key"),
	})
	if _, err := NewIssuer(rsaPEM, "test-issuer", 5*time.Minute); err == nil {
		t.Fatal("expected error for non-EC private key")
	}
}

func TestNewIssuerRejectsEmptyPEM(t *testing.T) {
	if _, err := NewIssuer(nil, "test-issuer", 5*time.Minute); err == nil {
		t.Fatal("expected error for empty PEM")
	}
}
