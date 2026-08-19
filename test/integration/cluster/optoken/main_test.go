package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The header optoken prints must satisfy CDS's server-side check: the
// production Verifier over the pinned public key, bound to method, path, and
// body.
func TestRunProducesAuthorizingHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "operator.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(dir, "body.json")
	body := []byte(`{"digest":"sha256:abc","image":"example.com/img:1"}`)
	if err := os.WriteFile(bodyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	header, err := run([]string{"optoken", keyPath, "POST", "/allowlist/digests", bodyPath})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.HasPrefix(header, "Bearer ") {
		t.Fatalf("header = %q, want a Bearer token", header)
	}

	req, err := http.NewRequest(http.MethodPost, "https://cds/allowlist/digests", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", header)
	if err := (operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}}).Authorize(req, body); err != nil {
		t.Fatalf("verifier rejected optoken's header: %v", err)
	}

	// The body binding must hold: a tampered body fails server-side.
	if err := (operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}}).Authorize(req, []byte(`{}`)); err == nil {
		t.Fatal("verifier accepted a token against a different body")
	}
}

func TestRunUsage(t *testing.T) {
	if _, err := run([]string{"optoken"}); err == nil {
		t.Fatal("run with no arguments did not fail")
	}
}
