package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func testOperatorKeysPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestLiveOperatorPolicyProvider(t *testing.T) {
	keysPEM := testOperatorKeysPEM(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/operator-keys" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Write(keysPEM)
	}))
	defer api.Close()

	provider, err := newLiveOperatorPolicyProvider(api.URL, api.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := operatorauth.ParsePublicKeysPEM(keysPEM)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := operatorauth.KeySetHash(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeysPEM != string(keysPEM) || got.SHA256 != wantHash {
		t.Fatalf("operator policy = %+v, want PEM and hash %s", got, wantHash)
	}
}

func TestLiveOperatorPolicyProviderFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
		want string
	}{
		{name: "CDS error", body: "not ready", code: http.StatusServiceUnavailable, want: "HTTP 503"},
		{name: "invalid key set", body: "not PEM", code: http.StatusOK, want: "parse active operator keys"},
		{name: "oversize", body: strings.Repeat("x", maxOperatorPolicyBytes+1), code: http.StatusOK, want: "exceed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				w.Write([]byte(tc.body))
			}))
			defer api.Close()
			provider, err := newLiveOperatorPolicyProvider(api.URL, api.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Active(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNewLiveOperatorPolicyProviderRequiresClientAndURL(t *testing.T) {
	if _, err := newLiveOperatorPolicyProvider("", http.DefaultClient); err == nil {
		t.Fatal("empty CDS URL accepted")
	}
	if _, err := newLiveOperatorPolicyProvider("https://cds", nil); err == nil {
		t.Fatal("nil client accepted")
	}
}
