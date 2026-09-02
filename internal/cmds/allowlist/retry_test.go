package allowlist

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// shortRetryDelay drops the retry backoff for a test so retries run in
// microseconds.
func shortRetryDelay(t *testing.T) {
	t.Helper()
	saved := retryDelay
	retryDelay = time.Microsecond
	t.Cleanup(func() { retryDelay = saved })
}

// connKillingCDS serves digests like servingCDS, but its listener closes the
// first n accepted connections before any bytes are exchanged — the client
// sees the same EOF / reset a mid-handshake teardown through a port-forward
// produces.
func connKillingCDS(t *testing.T, n int) (url string, accepts, requests *atomic.Int32) {
	t.Helper()
	var served atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	var count atomic.Int32
	srv.Listener = &killingListener{Listener: srv.Listener, kill: n, accepts: &count}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL, &count, &served
}

type killingListener struct {
	net.Listener
	mu      sync.Mutex
	kill    int
	accepts *atomic.Int32
}

func (l *killingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.accepts.Add(1)
	l.mu.Lock()
	killed := l.kill > 0
	if killed {
		l.kill--
	}
	l.mu.Unlock()
	if killed {
		conn.Close()
		return l.Accept()
	}
	return conn, nil
}

func TestAddRetriesTransientConnectionFailures(t *testing.T) {
	shortRetryDelay(t)
	// Kill retryAttempts-1 connections so success lands on the last allowed
	// attempt.
	url, accepts, requests := connKillingCDS(t, retryAttempts-1)
	keyPath := writeOperatorKey(t, t.TempDir())

	out, errb, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("add: %v (stderr: %s)", err, errb)
	}
	if !strings.Contains(out, "added "+digA) {
		t.Fatalf("expected added output, got %q", out)
	}
	if !strings.Contains(errb, "transient CDS connection failure (attempt 3/4)") {
		t.Fatalf("expected retry notes on the command stderr, got %q", errb)
	}
	if got := accepts.Load(); got != int32(retryAttempts) {
		t.Fatalf("expected %d connections (%d killed + 1 served), got %d", retryAttempts, retryAttempts-1, got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected the handler to see exactly 1 request, got %d", got)
	}
}

// countingAuthorizer counts Authorization mints; each retry attempt must
// re-mint rather than reuse a token.
type countingAuthorizer struct{ mints atomic.Int32 }

func (a *countingAuthorizer) Authorization(method, path string, body []byte) (string, error) {
	a.mints.Add(1)
	return "Bearer test", nil
}

func TestRetryReMintsOperatorTokenPerAttempt(t *testing.T) {
	shortRetryDelay(t)
	url, _, _ := connKillingCDS(t, 1)
	auth := &countingAuthorizer{}
	c := client{api: allowlistclient.NewClient(url), stderr: io.Discard}

	digest, err := types.ParseDigest(digA)
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	if err := c.AddDigest(context.Background(), digest, "registry/app@"+digA, auth); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := auth.mints.Load(); got != 2 {
		t.Fatalf("expected 2 token mints (1 per attempt), got %d", got)
	}
}

func TestAddGivesUpAfterBoundedAttempts(t *testing.T) {
	shortRetryDelay(t)
	url, accepts, _ := connKillingCDS(t, 1000)
	keyPath := writeOperatorKey(t, t.TempDir())

	_, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--insecure", "--operator-key", keyPath)
	if err == nil {
		t.Fatal("expected the add to fail")
	}
	if !isTransient(err) {
		t.Fatalf("expected the surfaced error to be the transient one, got %v", err)
	}
	if got := accepts.Load(); got != retryAttempts {
		t.Fatalf("expected exactly %d connection attempts, got %d", retryAttempts, got)
	}
}

func TestAddDoesNotRetryServedErrors(t *testing.T) {
	shortRetryDelay(t)
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	keyPath := writeOperatorKey(t, t.TempDir())

	_, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	var se *allowlistclient.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError {
		t.Fatalf("expected a 500 StatusError, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("expected exactly 1 request (no retry), got %d", requests)
	}
}

func TestRetryNotesEachAttemptOnStderr(t *testing.T) {
	shortRetryDelay(t)
	var notes strings.Builder
	c := client{stderr: &notes}
	calls := 0
	err := c.retry(context.Background(), func() error {
		calls++
		if calls == 1 {
			return fmt.Errorf("request failed: %w", io.EOF)
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("expected success on attempt 2, got err=%v calls=%d", err, calls)
	}
	if !strings.Contains(notes.String(), "transient CDS connection failure (attempt 1/4)") {
		t.Fatalf("expected a retry note, got %q", notes.String())
	}
}

func TestRetryTransientStopsWhenContextDone(t *testing.T) {
	shortRetryDelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var notes strings.Builder
	c := client{stderr: &notes}
	calls := 0
	err := c.retry(ctx, func() error {
		calls++
		return fmt.Errorf("request failed: %w", io.EOF)
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected the EOF to surface, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt under a cancelled context, got %d", calls)
	}
}

func TestRetryStopsWhenParentDeadlineExpired(t *testing.T) {
	shortRetryDelay(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	c := client{stderr: io.Discard}
	calls := 0
	err := c.retry(ctx, func() error {
		calls++
		return fmt.Errorf("request failed: %w", context.DeadlineExceeded)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the deadline error to surface, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt under an expired deadline, got %d", calls)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "deadline exceeded" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestIsTransient(t *testing.T) {
	// Wrapped the way the client surfaces them: url.Error / net.OpError
	// chains under mutate's "request failed" wrap.
	transient := []error{
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "https://localhost:28450/allowlist/digests", Err: io.EOF}),
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "https://localhost:28450", Err: io.ErrUnexpectedEOF}),
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: &net.OpError{Op: "write", Err: os.NewSyscallError("write", syscall.EPIPE)}}),
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}}),
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: timeoutErr{}}),
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: errors.New("http: server closed idle connection")}),
		// A failed collateral fetch inside handshake verification reached no
		// verdict; the ctx-done gate in retry, not the classifier, owns an
		// expired parent deadline.
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: &localverify.PeerVerificationError{
			Err: &localverify.CollateralError{Err: context.DeadlineExceeded},
		}}),
	}
	for _, err := range transient {
		if !isTransient(err) {
			t.Errorf("expected transient: %v", err)
		}
	}
	verdicts := []error{
		nil,
		context.Canceled,
		&allowlistclient.StatusError{Status: 500, Body: "boom"},
		// An attestation verdict is never retried, even when the verifier's
		// internals happened to wrap a transport-shaped error.
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: &localverify.PeerVerificationError{
			Err: fmt.Errorf("localverify: peer attestation failed: %w", localverify.ErrMeasurementNotAllowed),
		}}),
		fmt.Errorf("request failed: %w", &url.Error{Op: "Post", URL: "x", Err: &localverify.PeerVerificationError{
			Err: fmt.Errorf("parse report: %w", io.ErrUnexpectedEOF),
		}}),
	}
	for _, err := range verdicts {
		if isTransient(err) {
			t.Errorf("expected non-transient: %v", err)
		}
	}
}
