package attestproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// startUpstream returns a running fake attestation-api and its URL.
func startUpstream(t *testing.T, handler http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// serveProxy runs the proxy on a temp socket until the test ends.
func serveProxy(t *testing.T, cfg config) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "attest.sock")
	cfg.socket = sock
	if cfg.readHeaderTimeout == 0 {
		cfg.readHeaderTimeout = time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runContext(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("proxy serve: %v", err)
		}
	})
	// Wait for the socket to appear rather than sleeping a fixed interval.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return sock
}

func TestProxyForwardsOverSocket(t *testing.T) {
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Errorf("upstream saw path %s, want /attest", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want none forwarded without --api-key-file", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{}}`))
	}))
	sock := serveProxy(t, config{upstream: upstream, socketGID: 0})

	if _, err := attestationclient.NewClient("unix://"+sock).Attest(context.Background(), types.AttestRequest{}); err != nil {
		t.Fatalf("Attest over proxy socket: %v", err)
	}
}

func TestProxyInjectsAPIKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want Bearer s3cret (trailing newline trimmed)", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	sock := serveProxy(t, config{upstream: upstream, apiKeyFile: keyFile, socketGID: 0})

	if _, err := attestationclient.NewClient("unix://" + sock).Health(context.Background()); err != nil {
		t.Fatalf("Health over proxy socket: %v", err)
	}
}

func TestProxySocketPermissions(t *testing.T) {
	upstream := startUpstream(t, http.NotFoundHandler())
	sock := serveProxy(t, config{upstream: upstream, socketGID: os.Getegid()})

	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket (mode %s)", sock, fi.Mode())
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %#o, want 0660", got)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Gid) != os.Getegid() {
		t.Fatalf("socket gid = %d, want %d", st.Gid, os.Getegid())
	}
}

func TestProxyReportsUpstreamDown(t *testing.T) {
	// Nothing listens on the upstream; the proxy must answer 502, not hang.
	sock := serveProxy(t, config{upstream: "http://127.0.0.1:1", socketGID: 0})
	_, err := attestationclient.NewClient("unix://" + sock).Health(context.Background())
	var unexpErr *attestationclient.UnexpectedError
	if err == nil {
		t.Fatal("Health succeeded against a dead upstream")
	}
	if !errors.As(err, &unexpErr) || unexpErr.Status != http.StatusBadGateway {
		t.Fatalf("err = %v, want 502", err)
	}
}

func TestNewProxyRejectsBadConfig(t *testing.T) {
	upstream := startUpstream(t, http.NotFoundHandler())
	for _, tc := range []struct {
		name string
		cfg  config
	}{
		{"relative socket", config{socket: "rel.sock", upstream: upstream, readHeaderTimeout: time.Second}},
		{"bad upstream scheme", config{socket: "/tmp/x.sock", upstream: "ftp://x", readHeaderTimeout: time.Second}},
		{"missing key file", config{socket: "/tmp/x.sock", upstream: upstream, apiKeyFile: "/nonexistent", readHeaderTimeout: time.Second}},
		{"empty key file", config{socket: "/tmp/x.sock", upstream: upstream, apiKeyFile: writeKeyFile(t, "  \n"), readHeaderTimeout: time.Second}},
		{"nonpositive header timeout", config{socket: "/tmp/x.sock", upstream: upstream}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newProxy(tc.cfg); err == nil {
				t.Fatal("newProxy succeeded, want rejection")
			}
		})
	}
}

// The healthcheck subcommand is the DaemonSet's only liveness signal: it
// must succeed against a live proxied upstream and fail against a missing
// socket.
func TestHealthcheckCmd(t *testing.T) {
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	sock := serveProxy(t, config{upstream: upstream, socketGID: 0})

	cmd := newHealthcheckCmd()
	cmd.SetArgs([]string{"--socket", sock})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("healthcheck against live proxied upstream: %v", err)
	}

	missing := newHealthcheckCmd()
	missing.SetArgs([]string{"--socket", filepath.Join(t.TempDir(), "gone.sock")})
	if err := missing.Execute(); err == nil {
		t.Fatal("healthcheck succeeded against a missing socket")
	}
}

// A caller-supplied Authorization header must not survive the proxy: the
// injected key overwrites it (Header.Set), so socket callers cannot smuggle
// a stale or foreign key to the upstream.
func TestProxyOverwritesInboundAuthorization(t *testing.T) {
	keyFile := writeKeyFile(t, "s3cret")
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want the injected key overwriting the inbound header", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	sock := serveProxy(t, config{upstream: upstream, apiKeyFile: keyFile, socketGID: 0})

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	req, err := http.NewRequest(http.MethodGet, "http://unix/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer caller-supplied")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET over proxy socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func writeKeyFile(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
