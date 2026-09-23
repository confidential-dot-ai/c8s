package policystate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// TestAuthorityFingerprintIsOverTheDER pins that the fingerprint names the DER
// SubjectPublicKeyInfo, which is what a verifier reads out of a key file, not
// the raw 32 bytes a boot id uses.
func TestAuthorityFingerprintIsOverTheDER(t *testing.T) {
	got, err := AuthorityFingerprint(testPub())
	if err != nil {
		t.Fatalf("AuthorityFingerprint(pub) = _, %v, want no error", err)
	}
	der, err := x509.MarshalPKIXPublicKey(testPub())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey(pub) = _, %v, want no error", err)
	}
	if want := ContentDigest(der); got != want {
		t.Errorf("AuthorityFingerprint(pub) = %s, want %s", got, want)
	}
	if got == BootID(testPub()) {
		t.Errorf("AuthorityFingerprint(pub) = %s, want it to differ from BootID(pub)", got)
	}
}

func TestEncodeDecodeAuthorityKey(t *testing.T) {
	encoded, err := EncodeAuthorityKey(testPub())
	if err != nil {
		t.Fatalf("EncodeAuthorityKey(pub) = _, %v, want no error", err)
	}
	if strings.ContainsAny(encoded, "=+/") {
		t.Errorf("EncodeAuthorityKey(pub) = %s, want unpadded base64url", encoded)
	}
	back, err := DecodeAuthorityKey(encoded)
	if err != nil {
		t.Fatalf("DecodeAuthorityKey(%s) = _, %v, want no error", encoded, err)
	}
	if !back.Equal(testPub()) {
		t.Errorf("DecodeAuthorityKey(EncodeAuthorityKey(pub)) = %x, want %x", back, testPub())
	}
}

func TestAuthorityKeyRejects(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P256) = _, %v, want no error", err)
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey(ecdsa) = _, %v, want no error", err)
	}
	tests := []struct {
		name  string
		input string
	}{
		{"raw key bytes rather than DER", base64.RawURLEncoding.EncodeToString(testPub())},
		{"padded base64", base64.URLEncoding.EncodeToString(otherSPKI)},
		{"another key type", base64.RawURLEncoding.EncodeToString(otherSPKI)},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeAuthorityKey(tc.input)
			if err == nil {
				t.Errorf("DecodeAuthorityKey(%q) = %x, nil, want an error", tc.input, got)
			}
		})
	}
}

// TestAuthorityRejectsAShortKey keeps a truncated key from being fingerprinted:
// x509 marshals an ed25519.PublicKey of any length.
func TestAuthorityRejectsAShortKey(t *testing.T) {
	short := ed25519.PublicKey("short")
	if got, err := AuthorityFingerprint(short); err == nil {
		t.Errorf("AuthorityFingerprint(shortKey) = %s, nil, want an error", got)
	}
	if got, err := EncodeAuthorityKey(short); err == nil {
		t.Errorf("EncodeAuthorityKey(shortKey) = %s, nil, want an error", got)
	}
}
