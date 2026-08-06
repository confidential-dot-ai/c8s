package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAzure serves the token endpoint and a vault secrets endpoint from one
// TLS server, counting calls.
type fakeAzure struct {
	srv *httptest.Server

	tokenCalls  atomic.Int32
	secretCalls atomic.Int32

	tokenStatus  int
	tokenBody    string
	secret       string
	secretStatus int
	// authHeader records the last Authorization header the vault saw.
	authHeader atomic.Value
}

func newFakeAzure(t *testing.T) *fakeAzure {
	t.Helper()
	f := &fakeAzure{
		tokenStatus:  http.StatusOK,
		tokenBody:    `{"access_token":"tok-1","expires_in":3600}`,
		secret:       "vault-value",
		secretStatus: http.StatusOK,
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			f.tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("token form parse: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q", got)
			}
			if got := r.Form.Get("scope"); got != azureScope {
				t.Errorf("scope = %q", got)
			}
			if r.Form.Get("client_secret") == "" {
				t.Error("client_secret empty")
			}
			w.WriteHeader(f.tokenStatus)
			fmt.Fprint(w, f.tokenBody)
		case strings.HasPrefix(r.URL.Path, "/secrets/"):
			f.secretCalls.Add(1)
			f.authHeader.Store(r.Header.Get("Authorization"))
			if r.URL.Query().Get("api-version") != azureAPIVersion {
				t.Errorf("api-version = %q", r.URL.Query().Get("api-version"))
			}
			w.WriteHeader(f.secretStatus)
			if f.secretStatus == http.StatusOK {
				fmt.Fprintf(w, `{"value":%q,"id":"x"}`, f.secret)
			} else {
				fmt.Fprint(w, `{"error":{"code":"x","message":"y"}}`)
			}
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// config points an azureConfig at the fake with its CA trusted.
func (f *fakeAzure) config(cred AzureCredential, mappings map[string]AzureMapping) *azureConfig {
	c := newAzureConfig(cred, mappings)
	c.loginURL = f.srv.URL
	c.client = &http.Client{
		Timeout: azureTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    x509Pool(f.srv),
			MinVersion: tls.VersionTLS12,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

func x509Pool(s *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return pool
}

var testCred = AzureCredential{TenantID: "t", ClientID: "c", ClientSecret: "s"}

func TestAzureFetchDeliversVaultValue(t *testing.T) {
	f := newFakeAzure(t)
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	got, err := c.fetch(context.Background(), "/a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "vault-value" {
		t.Fatalf("value = %q", got)
	}
	if got := f.authHeader.Load().(string); got != "Bearer tok-1" {
		t.Fatalf("authorization = %q", got)
	}
	if c.last["/a"].Err != "" {
		t.Fatalf("last fetch recorded error: %q", c.last["/a"].Err)
	}
}

func TestAzureTokenCached(t *testing.T) {
	f := newFakeAzure(t)
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	for range 3 {
		if _, err := c.fetch(context.Background(), "/a"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1 (cached)", got)
	}
}

func TestAzureTokenRefreshedWhenExpired(t *testing.T) {
	f := newFakeAzure(t)
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err != nil {
		t.Fatal(err)
	}
	c.tokens.mu.Lock()
	c.tokens.expiry = time.Now().Add(-time.Minute)
	c.tokens.mu.Unlock()
	if _, err := c.fetch(context.Background(), "/a"); err != nil {
		t.Fatal(err)
	}
	if got := f.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2 (refresh after expiry)", got)
	}
}

func TestAzure401DropsTokenAndRetriesOnce(t *testing.T) {
	f := newFakeAzure(t)
	f.secretStatus = http.StatusUnauthorized
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil {
		t.Fatal("expected an error")
	}
	// One retry within the request: two vault calls, two token calls (the
	// second after invalidation).
	if got := f.secretCalls.Load(); got != 2 {
		t.Fatalf("secret calls = %d, want 2", got)
	}
	if got := f.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2 (invalidate then refetch)", got)
	}
}

func TestAzureVault404IsOpaqueErrorNotNotFound(t *testing.T) {
	f := newFakeAzure(t)
	f.secretStatus = http.StatusNotFound
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	_, err := c.fetch(context.Background(), "/a")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err == ErrNotFound {
		t.Fatal("a vault 404 must not masquerade as an absent path: that triggers the mint dance")
	}
	if c.last["/a"].Err == "" {
		t.Fatal("failure not recorded for status")
	}
}

func TestAzureRedirectIsRefused(t *testing.T) {
	f := newFakeAzure(t)
	f.secretStatus = http.StatusFound
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil {
		t.Fatal("a redirect must be an error, not a followed request")
	}
	if got := f.secretCalls.Load(); got != 1 {
		t.Fatalf("secret calls = %d, want 1 (no follow)", got)
	}
}

func TestAzureTokenFailure(t *testing.T) {
	f := newFakeAzure(t)
	f.tokenStatus = http.StatusBadRequest
	f.tokenBody = `{"error":"invalid_client"}`
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil {
		t.Fatal("expected a token failure")
	}
	if got := f.secretCalls.Load(); got != 0 {
		t.Fatalf("secret calls = %d, want 0 (no token, no vault call)", got)
	}
}

func TestAzureFetchRejectsOversizedValue(t *testing.T) {
	f := newFakeAzure(t)
	f.secret = strings.Repeat("x", 100)
	backend := NewExternalBackend(nil, nil, 8)
	backend.mu.Lock()
	backend.live = f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	backend.mapped = map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}}
	backend.mu.Unlock()
	if _, err := backend.Fetch(context.Background(), "/a"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected the size cap to refuse, got %v", err)
	}
}

func TestBackendFailsClosedWithoutCredential(t *testing.T) {
	b := NewExternalBackend(map[string]AzureMapping{"/a": {Vault: "https://v.vault.azure.net", Name: "s"}}, nil, 64)
	if !b.Mapped("/a") {
		t.Fatal("persisted mapping not loaded")
	}
	_, err := b.Fetch(context.Background(), "/a")
	if err != errNotConfigured {
		t.Fatalf("Fetch = %v, want errNotConfigured", err)
	}
}
