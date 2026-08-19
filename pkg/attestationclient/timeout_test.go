package attestationclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// hangingServer accepts the connection and never answers, which is what a
// hostile host running the attestation-api can always do.
func hangingServer(t *testing.T) *httptest.Server {
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
	return srv
}

// TestNewClientBoundsRequests pins the overall deadline on both constructions.
// http.DefaultClient has none, so without this a peer that never answers pins
// the calling goroutine for the process's life.
func TestNewClientBoundsRequests(t *testing.T) {
	if got := NewClient("https://attestation-api.example.com").httpClient.Timeout; got != requestTimeout {
		t.Errorf("routable client Timeout = %v, want %v", got, requestTimeout)
	}
	if got := NewClient("unix:///run/c8s/attest.sock").httpClient.Timeout; got != requestTimeout {
		t.Errorf("socket client Timeout = %v, want %v", got, requestTimeout)
	}
}

// TestHealthReturnsWithinItsTimeout proves the client's deadline reaches the
// request rather than only the dial: the server accepts and stalls.
func TestHealthReturnsWithinItsTimeout(t *testing.T) {
	srv := hangingServer(t)
	c := NewClientWithHTTP(srv.URL, &http.Client{Timeout: 100 * time.Millisecond})

	done := make(chan error, 1)
	go func() { _, err := c.Health(context.Background()); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Health returned no error against a server that never answers")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Health did not return within its timeout")
	}
}

// TestHealthReturnsOnContextCancel pins cancellation propagation.
func TestHealthReturnsOnContextCancel(t *testing.T) {
	srv := hangingServer(t)
	c := NewClient(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Health(ctx); done <- err }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Health error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Health did not return after context cancel")
	}
}
