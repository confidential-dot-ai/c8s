package issuer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestRateLimitMiddlewareKeysBySourceIP pins that limiter entries are keyed by
// the source IP alone: a client reconnecting from a new ephemeral port must
// not get a fresh bucket.
func TestRateLimitMiddlewareKeysBySourceIP(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.5.5.5:1111"
	h.ServeHTTP(first, req1)
	if first.Code != http.StatusOK {
		t.Fatalf("first request code = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.5.5.5:2222"
	h.ServeHTTP(second, req2)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP from new port code = %d, want 429", second.Code)
	}
}

func TestNewIPRateLimiterRejectsNonPositiveMaxEntries(t *testing.T) {
	for _, maxEntries := range []int{0, -1} {
		if _, err := NewIPRateLimiter(rate.Limit(10), 20, maxEntries); err == nil {
			t.Errorf("maxEntries=%d: expected error, got nil", maxEntries)
		}
	}
}

func TestRateLimiterEviction(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(10), 20, 10000)
	if err != nil {
		t.Fatal(err)
	}

	rl.getLimiter("10.0.0.1")
	rl.getLimiter("10.0.0.2")
	rl.getLimiter("10.0.0.3")

	rl.mu.Lock()
	if len(rl.limiters) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rl.limiters))
	}

	oldTime := time.Now().Add(-10 * time.Minute)
	rl.limiters["10.0.0.1"].lastSeen = oldTime
	rl.limiters["10.0.0.2"].lastSeen = oldTime
	rl.mu.Unlock()

	rl.evict(5 * time.Minute)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.limiters) != 1 {
		t.Errorf("expected 1 entry after eviction, got %d", len(rl.limiters))
	}
	if _, ok := rl.limiters["10.0.0.3"]; !ok {
		t.Error("expected 10.0.0.3 to survive eviction")
	}
}

func TestRateLimiterMaxEntries(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(10), 20, 3)
	if err != nil {
		t.Fatal(err)
	}

	rl.getLimiter("10.0.0.1")
	rl.getLimiter("10.0.0.2")
	rl.getLimiter("10.0.0.3")

	rl.mu.Lock()
	if len(rl.limiters) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rl.limiters))
	}
	rl.mu.Unlock()

	rl.getLimiter("10.0.0.4")

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.limiters) != 3 {
		t.Errorf("expected 3 entries after cap, got %d", len(rl.limiters))
	}
}
