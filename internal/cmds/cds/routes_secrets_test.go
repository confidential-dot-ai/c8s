package cds

import (
	"net/http"
	"net/http/httptest"
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
