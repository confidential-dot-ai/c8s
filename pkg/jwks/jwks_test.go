package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestFromPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if jwk.KeyID == "" {
		t.Error("kid should be non-empty")
	}
	if jwk.Use != "sig" {
		t.Errorf("use = %q, want sig", jwk.Use)
	}
	if jwk.Algorithm != string(jose.ES256) {
		t.Errorf("alg = %q, want ES256", jwk.Algorithm)
	}
}

func TestThumbprintStability(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwk1, _ := FromPublicKey(&key.PublicKey)
	jwk2, _ := FromPublicKey(&key.PublicKey)

	if jwk1.KeyID != jwk2.KeyID {
		t.Errorf("kid changed across calls: %s vs %s", jwk1.KeyID, jwk2.KeyID)
	}
}

func TestThumbprintUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jwk, err := FromPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if seen[jwk.KeyID] {
			t.Fatalf("duplicate kid after %d keys", len(seen))
		}
		seen[jwk.KeyID] = true
	}
}

func TestThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	thumb, err := Thumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if thumb == "" {
		t.Error("thumbprint should be non-empty")
	}

	// Thumbprint must equal the kid produced by FromPublicKey.
	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if thumb != jwk.KeyID {
		t.Errorf("Thumbprint = %q, FromPublicKey kid = %q", thumb, jwk.KeyID)
	}
}

func TestThumbprintStable(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t1, _ := Thumbprint(&key.PublicKey)
	t2, _ := Thumbprint(&key.PublicKey)
	if t1 != t2 {
		t.Errorf("thumbprint changed across calls: %s vs %s", t1, t2)
	}
}

// invalidKey returns an ECDSA public key on a supported curve (P-256) but with
// oversized coordinates. go-jose's thumbprint rejects coordinates larger than
// the curve size with an error (rather than panicking), exercising the error
// paths of FromPublicKey and Thumbprint deterministically.
func invalidKey() *ecdsa.PublicKey {
	// P-256 coordinates are 32 bytes; 64 bytes is too large.
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64*8)
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     tooLarge,
		Y:     tooLarge,
	}
}

func TestFromPublicKeyError(t *testing.T) {
	jwk, err := FromPublicKey(invalidKey())
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	if jwk.KeyID != "" || jwk.Key != nil {
		t.Errorf("expected zero JSONWebKey on error, got %+v", jwk)
	}
}

func TestThumbprintError(t *testing.T) {
	thumb, err := Thumbprint(invalidKey())
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	if thumb != "" {
		t.Errorf("expected empty thumbprint on error, got %q", thumb)
	}
}

func TestMarshalSetMultiple(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk1, _ := FromPublicKey(&k1.PublicKey)
	jwk2, _ := FromPublicKey(&k2.PublicKey)

	data, err := MarshalSet(jwk1, jwk2)
	if err != nil {
		t.Fatal(err)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(set.Keys))
	}
}

func TestMarshalSetEmpty(t *testing.T) {
	data, err := MarshalSet()
	if err != nil {
		t.Fatal(err)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(set.Keys))
	}
}

func TestMarshalSet(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := FromPublicKey(&key.PublicKey)

	data, err := MarshalSet(jwk)
	if err != nil {
		t.Fatal(err)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(set.Keys))
	}
	if set.Keys[0].KeyID != jwk.KeyID {
		t.Error("round-tripped kid mismatch")
	}
}
