package cds

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"golang.org/x/time/rate"
)

func secretsRouter(t *testing.T, enabled bool) http.Handler {
	t.Helper()
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler:  AttestHandler{Challenges: &cs},
		ReadyFn:        func() bool { return true },
		RateLimiter:    limiter,
		MaxRequestSize: 65536,
	}
	if enabled {
		// A bare handler: routing is what is under test, so every request that
		// reaches it is refused for want of a client certificate.
		deps.SecretsHandler = &secrets.Handler{}
		deps.SecretsChallenges = &secretsCS
		deps.SecretsOperator = &secrets.OperatorHandler{Store: secrets.NewMemoryStore(8, 64)}
		deps.SecretsExplain = &secrets.ExplainHandler{}
	}
	return newRouter(deps)
}

func get(t *testing.T, h http.Handler, method, path string) int {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w.Code
}

// The challenge route is "/secrets" exactly and the secret route is everything
// below it, so neither shadows the other and no store path is unreachable.
func TestRouter_SecretsChallengeDoesNotShadowSecretPaths(t *testing.T) {
	r := secretsRouter(t, true)

	if code := get(t, r, http.MethodPost, "/secrets"); code != http.StatusOK {
		t.Fatalf("POST /secrets = %d, want 200 (a challenge)", code)
	}
	// A secret literally named /challenge must still route to the handler, not
	// to the challenge endpoint.
	for _, p := range []string{"/secrets/challenge", "/secrets/api/db", "/secrets/a/b/c"} {
		if code := get(t, r, http.MethodGet, p); code == http.StatusNotFound {
			t.Fatalf("GET %s = 404: the route did not reach the secrets handler", p)
		}
	}
}

// With --secrets off, nothing under /secrets is served at all.
func TestRouter_SecretsUnroutedWhenDisabled(t *testing.T) {
	r := secretsRouter(t, false)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/secrets"},
		{http.MethodGet, "/secrets/api/db"},
		{http.MethodPost, "/secrets/api/db"},
		{http.MethodPut, "/secrets/api/db"},
		{http.MethodGet, "/secrets-explain/" + strings.Repeat("a", 64)},
	} {
		if code := get(t, r, tc.method, tc.path); code != http.StatusNotFound {
			t.Fatalf("%s %s = %d with secrets disabled, want 404", tc.method, tc.path, code)
		}
	}
}

// The issuance and secrets challenge pools are distinct, so a nonce minted for
// one endpoint is not redeemable at the other.
func TestRouter_SecretsChallengePoolIsSeparate(t *testing.T) {
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler:     AttestHandler{Challenges: &cs},
		ReadyFn:           func() bool { return true },
		RateLimiter:       limiter,
		MaxRequestSize:    65536,
		SecretsHandler:    &secrets.Handler{},
		SecretsChallenges: &secretsCS,
		SecretsOperator:   &secrets.OperatorHandler{Store: secrets.NewMemoryStore(8, 64)},
		SecretsExplain:    &secrets.ExplainHandler{},
	}
	_ = newRouter(deps)

	issued := cs.Create()
	if secretsCS.Consume(issued[:]) {
		t.Fatal("an issuance challenge was redeemable against the secrets pool")
	}
	secretsIssued := secretsCS.Create()
	if cs.Consume(secretsIssued[:]) {
		t.Fatal("a secrets challenge was redeemable against the issuance pool")
	}
}

// PUT is the operator's door onto the same paths, so it is authorized by the
// pinned operator key rather than by a mesh leaf and sandbox token. With no
// authorizer wired, it refuses.
func TestRouter_SecretsPutIsOperatorAuthorized(t *testing.T) {
	r := secretsRouter(t, true)
	if code := get(t, r, http.MethodPut, "/secrets/api/db"); code != http.StatusUnauthorized {
		t.Fatalf("PUT /secrets/api/db = %d, want 401", code)
	}
}

// The operator body cap is the allowlist one, not MaxRequestSize: a secret
// value is base64 inside JSON and would not fit the attestation-sized bound.
func TestRouter_SecretsPutUsesTheAllowlistWriteCap(t *testing.T) {
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	var seen int
	deps := dependencies{
		AttestHandler:     AttestHandler{Challenges: &cs},
		ReadyFn:           func() bool { return true },
		RateLimiter:       limiter,
		MaxRequestSize:    8,
		SecretsHandler:    &secrets.Handler{},
		SecretsChallenges: &secretsCS,
		SecretsExplain:    &secrets.ExplainHandler{},
		SecretsOperator: &secrets.OperatorHandler{
			Store:        secrets.NewMemoryStore(8, 4096),
			MaxBodyBytes: allowlistWriteBodyCap,
			Authorize:    func(_ *http.Request, body []byte) error { seen = len(body); return nil },
		},
	}
	r := newRouter(deps)

	value := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 512))
	body := `{"value":"` + value + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/secrets/api/db", strings.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body)
	}
	if seen != len(body) {
		t.Fatalf("authorizer saw %d bytes, want the whole %d-byte body", seen, len(body))
	}
}

// The diagnostic is a sibling of /secrets, not a path beneath it. chi prefers a
// literal segment over a wildcard, so had it been mounted at
// /secrets/explain/... every secret stored under /explain/ would have become
// unreachable — a store path silently shadowed by a route.
func TestRouter_ExplainDoesNotShadowSecretPaths(t *testing.T) {
	r := secretsRouter(t, true)

	sandbox := strings.Repeat("a", 64)
	if code := get(t, r, http.MethodGet, "/secrets-explain/"+sandbox); code != http.StatusUnauthorized {
		t.Fatalf("GET /secrets-explain = %d, want 401 (operator-authorized)", code)
	}
	// A secret literally under /explain still reaches the release handler,
	// which refuses it for want of a client certificate rather than 404ing.
	for _, p := range []string{"/secrets/explain", "/secrets/explain/" + sandbox, "/secrets/explain/db"} {
		if code := get(t, r, http.MethodGet, p); code == http.StatusNotFound {
			t.Fatalf("GET %s = 404: the explain route shadowed a store path", p)
		}
	}
}
