package operatorauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func keysetTestKey(t *testing.T, curve elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return &key.PublicKey
}

func TestKeySetDigestCanonical(t *testing.T) {
	a := keysetTestKey(t, elliptic.P256())
	b := keysetTestKey(t, elliptic.P384())

	ab, err := KeySetDigest([]*ecdsa.PublicKey{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(ab) != KeySetDigestSize {
		t.Fatalf("digest size = %d, want %d", len(ab), KeySetDigestSize)
	}

	ba, err := KeySetDigest([]*ecdsa.PublicKey{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("digest depends on key order")
	}

	dup, err := KeySetDigest([]*ecdsa.PublicKey{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, dup) {
		t.Fatal("digest depends on duplicate keys")
	}

	aOnly, err := KeySetDigest([]*ecdsa.PublicKey{a})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ab, aOnly) {
		t.Fatal("different key sets digest identically")
	}
}

func TestKeySetDigestEmptySetIsDefined(t *testing.T) {
	got, err := KeySetDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(keySetDomain))
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("empty-set digest = %x, want SHA-256 of the domain %x", got, want)
	}
	// The empty set must stay distinct from the unset config-claims sentinel.
	if bytes.Equal(got, make([]byte, KeySetDigestSize)) {
		t.Fatal("empty-set digest collides with the all-zero unset sentinel")
	}
}

// KeySetHash and KeySetDigest are one commitment in two encodings: the hash is
// the lowercase-hex of the digest. This guards against the two drifting apart
// again (the reason they were converged).
func TestKeySetHashIsHexOfKeySetDigest(t *testing.T) {
	keys := []*ecdsa.PublicKey{keysetTestKey(t, elliptic.P256()), keysetTestKey(t, elliptic.P384())}
	digest, err := KeySetDigest(keys)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := KeySetHash(keys)
	if err != nil {
		t.Fatal(err)
	}
	if hash != hex.EncodeToString(digest) {
		t.Fatalf("KeySetHash = %s, want hex(KeySetDigest) = %s", hash, hex.EncodeToString(digest))
	}
}
