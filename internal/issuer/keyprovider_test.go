package issuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jwksTestJSON(t *testing.T, kid string, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatalf("add key: %v", err)
	}
	buf, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	return buf
}

func jwksTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwksTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func jwksServer(t *testing.T, kid string, pub *ecdsa.PublicKey) *httptest.Server {
	t.Helper()
	buf := jwksTestJSON(t, kid, pub)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	}))
}

// TestJWKSKeyProviderUsesProvidedClient pins that a caller-supplied HTTP
// client carries every JWKS fetch: the URL host is unresolvable, so only the
// injected transport can serve it.
func TestJWKSKeyProviderUsesProvidedClient(t *testing.T) {
	key := jwksTestKey(t)
	buf := jwksTestJSON(t, "kid-1", &key.PublicKey)
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(buf)),
			Request:    r,
		}, nil
	})}

	p, err := NewJWKSKeyProvider(context.Background(), "http://jwks.invalid/.well-known/jwks.json", time.Minute, client, jwksTestLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	got, err := p.PublicKey("kid-1")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Fatal("resolved key does not match served key")
	}
}

func TestJWKSKeyProviderNilClientDefaults(t *testing.T) {
	key := jwksTestKey(t)
	buf := jwksTestJSON(t, "kid-1", &key.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	p, err := NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, nil, jwksTestLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	if _, err := p.PublicKey("kid-1"); err != nil {
		t.Fatalf("PublicKey with defaulted client: %v", err)
	}
}

// TestJWKSKeyProviderPicksUpRotatedKid drives a CDS key rotation: the cached
// set misses the new kid, a force-refresh fetches the rotated set, and both
// the rotation lookup and subsequent cached lookups succeed. The refresh
// counter must advance once for the initial fetch and once for the kid miss.
func TestJWKSKeyProviderPicksUpRotatedKid(t *testing.T) {
	oldKey := jwksTestKey(t)
	newKey := jwksTestKey(t)

	var current atomic.Value
	current.Store(jwksTestJSON(t, "kid-1", &oldKey.PublicKey))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(current.Load().([]byte))
	}))
	t.Cleanup(srv.Close)

	before := testutil.ToFloat64(jwksRefreshesTotal)
	p, err := NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), jwksTestLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	if _, err := p.PublicKey("kid-1"); err != nil {
		t.Fatalf("PublicKey pre-rotation: %v", err)
	}

	current.Store(jwksTestJSON(t, "kid-2", &newKey.PublicKey))
	// The jwx cache applies force-refreshes asynchronously; retry the lookup,
	// resetting the once-per-second guard so every attempt may refresh again.
	var got *ecdsa.PublicKey
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err = p.PublicKey("kid-2")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("PublicKey post-rotation: %v", err)
		}
		p.mu.Lock()
		p.lastForce = time.Time{}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	if !got.Equal(&newKey.PublicKey) {
		t.Fatal("post-rotation key does not match rotated key")
	}
	// Cached lookups after the refresh must not need (rate-limited) refreshes.
	if _, err := p.PublicKey("kid-2"); err != nil {
		t.Fatalf("PublicKey cached post-rotation: %v", err)
	}
	if delta := testutil.ToFloat64(jwksRefreshesTotal) - before; delta < 2 {
		t.Fatalf("jwks refreshes delta = %v, want >= 2 (initial fetch + kid-miss refresh)", delta)
	}
}

func TestNewCertKeyProvider(t *testing.T) {
	ca, err := NewCA("kp", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	p, err := NewCertKeyProvider(ca.Cert)
	if err != nil {
		t.Fatalf("NewCertKeyProvider: %v", err)
	}
	// kid is ignored for the cert-pinned provider.
	got, err := p.PublicKey("anything")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !got.Equal(ca.Key.Public()) {
		t.Error("returned public key does not match CA key")
	}
}

func TestNewCertKeyProviderRejectsNonECDSA(t *testing.T) {
	// A leaf cert built around a non-ECDSA key is overkill; instead craft a
	// cert whose PublicKey is replaced with a non-ECDSA type.
	ca, err := NewCA("kp", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	bad := *ca.Cert
	bad.PublicKey = "not-a-key"
	if _, err := NewCertKeyProvider(&bad); err == nil {
		t.Fatal("expected error for non-ECDSA cert public key")
	}
}

func TestJWKSKeyProviderRejectsEmptyKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	p, err := NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), jwksTestLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	if _, err := p.PublicKey(""); err == nil {
		t.Fatal("expected empty kid to be rejected")
	}
}

func TestJWKSKeyProviderKidMiss(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	p, err := NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), jwksTestLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	// First miss triggers a force-refresh which still won't find the kid.
	if _, err := p.PublicKey("missing-kid"); err == nil {
		t.Fatal("expected kid miss to error")
	}
	// Second miss within a second is refresh rate-limited.
	if _, err := p.PublicKey("missing-kid"); err == nil {
		t.Fatal("expected rate-limited kid miss to error")
	}
}

func TestNewJWKSKeyProviderInitialFetchFailureDoesNotError(t *testing.T) {
	// A server that 500s: initial fetch fails but constructor still succeeds
	// (it logs a warning and retries lazily).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, err := NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), jwksTestLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider should tolerate initial fetch failure: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}
