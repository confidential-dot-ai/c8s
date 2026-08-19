package readiness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// healthServer returns an httptest server whose /health returns the given
// status string, plus an attestationclient.Client pointed at it.
func healthServer(t *testing.T, status string, code int) attestationclient.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if code != 0 && code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.HealthResponse{Status: status})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return attestationclient.NewClientWithHTTP(srv.URL, srv.Client())
}

// hangingHealthServer accepts the request and never answers, the shape a
// wedged attestation-api takes on the wire.
func hangingHealthServer(t *testing.T) attestationclient.Client {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanup is LIFO: release the handler before Close waits on it.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return attestationclient.NewClientWithHTTP(srv.URL, srv.Client())
}

// TestCheckBoundsAHungProbe pins the per-check deadline: without one, check
// parks forever on a peer that never responds and /readyz keeps serving the
// last stored result.
func TestCheckBoundsAHungProbe(t *testing.T) {
	c := NewChecker(hangingHealthServer(t), 100*time.Millisecond)
	c.SetReady(true)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.check(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("check did not return within the per-check timeout")
	}

	// The lower bound distinguishes a deadline derived from the interval from
	// one that fires immediately.
	if d := time.Since(start); d < 40*time.Millisecond || d > time.Second {
		t.Errorf("check took %v, want about interval/2 (50ms)", d)
	}
	if c.Ready() {
		t.Error("readiness stayed true after a hung probe")
	}
}

// TestRunReturnsOnContextCancelWithHungAPI proves the per-check ctx still
// derives from the loop ctx.
func TestRunReturnsOnContextCancelWithHungAPI(t *testing.T) {
	c := NewChecker(hangingHealthServer(t), time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestCheckerInitiallyNotReady(t *testing.T) {
	c := NewChecker(healthServer(t, "ok", http.StatusOK), time.Second)
	if c.Ready() {
		t.Error("a fresh checker should not be ready before its first check")
	}
}

func TestSetReady(t *testing.T) {
	c := NewChecker(healthServer(t, "ok", http.StatusOK), time.Second)
	c.SetReady(true)
	if !c.Ready() {
		t.Error("Ready() = false after SetReady(true)")
	}
	c.SetReady(false)
	if c.Ready() {
		t.Error("Ready() = true after SetReady(false)")
	}
}

func TestRunBecomesReadyOnHealthyAPI(t *testing.T) {
	c := NewChecker(healthServer(t, "ok", http.StatusOK), time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx)

	waitFor(t, func() bool { return c.Ready() }, "checker to become ready")
}

func TestRunStaysNotReadyOnUnhealthyStatus(t *testing.T) {
	c := NewChecker(healthServer(t, "degraded", http.StatusOK), time.Hour)
	c.SetReady(true) // ensure check actually flips it to false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx)

	waitFor(t, func() bool { return !c.Ready() }, "checker to become not-ready")
}

func TestRunNotReadyOnHTTPError(t *testing.T) {
	c := NewChecker(healthServer(t, "", http.StatusInternalServerError), time.Hour)
	c.SetReady(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.Run(ctx)

	waitFor(t, func() bool { return !c.Ready() }, "checker to become not-ready on error")
}

func TestRunReturnsOnContextCancel(t *testing.T) {
	c := NewChecker(healthServer(t, "ok", http.StatusOK), time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
