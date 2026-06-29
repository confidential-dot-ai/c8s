package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/ear"
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
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func callJWKS(t *testing.T, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestHandleJWKSDynamicFunc(t *testing.T) {
	want := []byte(`{"keys":["dynamic"]}`)
	h := HandleJWKS(ear.Issuer{}, func() []byte { return want })

	rec := callJWKS(t, h)
	if rec.Body.String() != string(want) {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestHandleJWKSStaticFromIssuer(t *testing.T) {
	iss, err := ear.NewIssuer(testKeyPEM(t), "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	h := HandleJWKS(iss, nil)

	rec := callJWKS(t, h)
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.Keys))
	}
}

func TestHandleJWKSEmptyWhenNoKey(t *testing.T) {
	// A zero-value Issuer has no key, so static mode serves an empty set.
	h := HandleJWKS(ear.Issuer{}, nil)

	rec := callJWKS(t, h)
	if rec.Body.String() != `{"keys":[]}` {
		t.Errorf("body = %q, want empty key set", rec.Body.String())
	}
}
