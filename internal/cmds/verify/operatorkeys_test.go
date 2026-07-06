package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startKeysTLSServer serves /operator-keys over TLS and returns the base URL
// plus the hex SHA-256 of its serving certificate (what the attested-cert pin
// expects).
func startKeysTLSServer(t *testing.T, handler http.HandlerFunc) (base, certSHA256 string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

func operatorPubPEM(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), hex.EncodeToString(sum[:])
}

func TestFetchOperatorKeyFingerprints(t *testing.T) {
	pubPEM, wantFP := operatorPubPEM(t)
	base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/operator-keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pubPEM)
	})

	fps, note, err := fetchOperatorKeyFingerprints(context.Background(), base, "", certSHA, 5*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if note != "" {
		t.Fatalf("unexpected note: %q", note)
	}
	if len(fps) != 1 || fps[0] != wantFP {
		t.Fatalf("fingerprints = %v, want [%s]", fps, wantFP)
	}
}

// TestFetchOperatorKeysRejectsCertMismatch proves the attested-cert binding: a
// server presenting a different cert than the one whose attestation was
// verified must be rejected, so a MITM on the key fetch cannot inject keys.
func TestFetchOperatorKeysRejectsCertMismatch(t *testing.T) {
	pubPEM, _ := operatorPubPEM(t)
	base, _ := startKeysTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pubPEM)
	})

	wrong := strings.Repeat("ab", 32) // a sha256 that is not the serving cert's
	_, _, err := fetchOperatorKeyFingerprints(context.Background(), base, "", wrong, 5*time.Second)
	if err == nil {
		t.Fatal("expected a cert mismatch to fail the fetch")
	}
}

func TestFetchOperatorKeys404MeansDisabled(t *testing.T) {
	base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no operator keys configured", http.StatusNotFound)
	})

	fps, note, err := fetchOperatorKeyFingerprints(context.Background(), base, "", certSHA, 5*time.Second)
	if err != nil {
		t.Fatalf("404 should not be an error, got %v", err)
	}
	if len(fps) != 0 || note == "" {
		t.Fatalf("expected no fingerprints and an explanatory note, got fps=%v note=%q", fps, note)
	}
}
