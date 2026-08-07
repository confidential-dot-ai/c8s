package issuer

import (
	"context"
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

func TestRateLimitMiddlewareAllowsThenRejects(t *testing.T) {
	// burst=1, rate=0 -> first request allowed, second rejected.
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	var served int
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	h.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first request: code = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: code = %d, want 429", second.Code)
	}
	if served != 1 {
		t.Fatalf("handler served %d times, want 1", served)
	}
}

func TestRateLimitMiddlewareHandlesPortlessRemoteAddr(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(100), 10, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "/run/cds.sock" // no host:port
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestIPRateLimiterEvictionLoopStopsOnCancel(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(100), 10, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rl.EvictionLoop(ctx, time.Millisecond, time.Millisecond)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EvictionLoop did not return after cancel")
	}
}

// --- keyed limiting ---

// The point of the keyed middleware: two callers arriving from one address get
// one bucket each, so exhausting yours leaves mine untouched.
func TestRateLimitByGivesOneBucketPerKey(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	var key string
	h := RateLimitBy(rl, func(*http.Request) string { return key }, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	send := func() int {
		r := httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
		r.RemoteAddr = "10.0.0.7:34567" // one node address for every caller
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	key = "sandbox:aaa"
	if code := send(); code != http.StatusOK {
		t.Fatalf("first request for aaa = %d, want 200", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("second request for aaa = %d, want 429 (its own burst is spent)", code)
	}
	key = "sandbox:bbb"
	if code := send(); code != http.StatusOK {
		t.Fatalf("a different sandbox from the same address = %d, want 200", code)
	}
}

// A caller that names no key is charged to its address, so withholding an
// identity is not a way out of the limit.
func TestRateLimitByFallsBackToTheAddress(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitBy(rl, func(*http.Request) string { return "" }, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	send := func(addr string) int {
		r := httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := send("10.0.0.7:1"); code != http.StatusOK {
		t.Fatalf("first = %d, want 200", code)
	}
	if code := send("10.0.0.7:2"); code != http.StatusTooManyRequests {
		t.Fatalf("same address, different port = %d, want 429 (one bucket per address)", code)
	}
	if code := send("10.0.0.8:1"); code != http.StatusOK {
		t.Fatalf("a different address = %d, want 200", code)
	}
}

// Keys are namespaced, so a sandbox ID shaped like an address cannot name the
// bucket that address is charged to.
func TestRateLimitKeyNamespacesDoNotCollide(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitBy(rl, func(r *http.Request) string { return r.Header.Get("X-Key") }, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	send := func(key string) int {
		r := httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
		r.RemoteAddr = "10.0.0.7:1"
		if key != "" {
			r.Header.Set("X-Key", key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// Spend the address bucket.
	if code := send(""); code != http.StatusOK {
		t.Fatalf("address request = %d, want 200", code)
	}
	if code := send(""); code != http.StatusTooManyRequests {
		t.Fatalf("address bucket should be spent, got %d", code)
	}
	// A sandbox whose ID is that same address string is a different bucket.
	if code := send("sandbox:10.0.0.7"); code != http.StatusOK {
		t.Fatalf("an address-shaped sandbox ID shares the address bucket: %d", code)
	}
}
