package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestValidateBoundOperatorPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keysPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	hash, err := operatorauth.KeySetHash([]*ecdsa.PublicKey{&key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}

	if err := validateBoundOperatorPolicy("", ""); err != nil {
		t.Fatalf("empty optional policy: %v", err)
	}
	if err := validateBoundOperatorPolicy(keysPEM, hash); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	for _, tc := range []struct {
		name, keys, hash string
	}{
		{name: "missing PEM", hash: hash},
		{name: "missing hash", keys: keysPEM},
		{name: "invalid PEM", keys: "not PEM", hash: hash},
		{name: "different canonical set", keys: keysPEM, hash: strings.Repeat("a1", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateBoundOperatorPolicy(tc.keys, tc.hash); err == nil {
				t.Fatal("invalid operator policy passed")
			}
		})
	}
}
