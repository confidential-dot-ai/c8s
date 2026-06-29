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
