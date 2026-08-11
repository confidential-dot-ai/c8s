package join

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ramTempDir returns a tmpfs-backed temp dir; RunJoin refuses to stage the
// token anywhere else.
func ramTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/dev/shm", "c8s-join-")
	if err != nil {
		t.Skipf("no tmpfs temp dir available: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// joinConfig returns a JoinConfig pointing at server with outputs in a temp
// dir.
func joinConfig(t *testing.T, apiURL, serverAddr string) JoinConfig {
	t.Helper()
	dir := ramTempDir(t)
	return JoinConfig{
		ServerAddr:        serverAddr,
		AttestationAPIURL: apiURL,
		Platform:          "tdx",
		TokenOut:          filepath.Join(dir, "join-token"),
		FragmentOut:       filepath.Join(dir, "50-join.yaml"),
		SupervisorPort:    9345,
		Timeout:           10 * time.Second,
	}
}

// joinServer starts a TLS httptest server with an attested RA-TLS serving
// cert, the shape join-release presents.
func joinServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(key, &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: []byte(tdxEnvelope)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// serverHostPort strips the scheme off an httptest server URL.
func serverHostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

// TestJoinExchangeE2E runs the real RunRelease and RunJoin against each other
// over localhost with one shared fake attestation-api: mutual RA-TLS, client
// cert demanded and verified, token staged for rke2.
func TestJoinExchangeE2E(t *testing.T) {
	api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))

	relCfg := releaseConfig(t)
	relCfg.AttestationAPIURL = api.URL
	if err := os.WriteFile(relCfg.TokenPath, []byte("K10cafe::node:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	relCfg.ListenAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRelease(ctx, relCfg, ln) }()
	waitForListen(t, relCfg.ListenAddr, done)

	cfg := joinConfig(t, api.URL, relCfg.ListenAddr)
	if err := RunJoin(context.Background(), cfg); err != nil {
		t.Fatalf("RunJoin: %v", err)
	}

	token, err := os.ReadFile(cfg.TokenOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != "K10cafe::node:secret\n" {
		t.Errorf("staged token = %q", token)
	}
	assertMode(t, cfg.TokenOut, 0o600)

	var frag rke2Fragment
	fragBytes, err := os.ReadFile(cfg.FragmentOut)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(fragBytes, &frag); err != nil {
		t.Fatal(err)
	}
	wantServer := "https://127.0.0.1:9345"
	if frag.Server != wantServer {
		t.Errorf("fragment server = %q, want %q", frag.Server, wantServer)
	}
	if frag.TokenFile != cfg.TokenOut {
		t.Errorf("fragment token-file = %q, want %q", frag.TokenFile, cfg.TokenOut)
	}
	assertMode(t, cfg.FragmentOut, 0o600)

	cancel()
	<-done
}

// TestJoinRefusesMismatchedServer: the client's verifier reports the server's
// registers differ from its own; the handshake must fail and nothing may be
// staged.
func TestJoinRefusesMismatchedServer(t *testing.T) {
	// Call 1 is ownRefs, later calls are the server's cert during handshake
	// (the client may retry the handshake internally).
	api := newFakeAPI(t, func(call int, _ types.VerifyRequest) types.VerifyResponse {
		if call == 1 {
			return verifyResp(digestA, rtmr1A, rtmr2A, true, true)
		}
		return verifyResp(digestB, rtmr1A, rtmr2A, true, true)
	})
	srv := joinServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request reached the server despite a failed verification")
	}))

	cfg := joinConfig(t, api.URL, serverHostPort(t, srv))
	err := RunJoin(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected RunJoin to fail")
	}
	if !errors.Is(err, ErrPolicyMismatch) && !strings.Contains(err.Error(), ErrPolicyMismatch.Error()) {
		t.Fatalf("err = %v, want policy mismatch", err)
	}
	assertAbsent(t, cfg.TokenOut)
	assertAbsent(t, cfg.FragmentOut)
}

// TestJoinServerErrors: an attested, same-image server that refuses or
// misbehaves must surface an error and stage nothing.
func TestJoinServerErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"denied", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "join denied", http.StatusForbidden)
		}},
		{"not ready", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "join token not ready", http.StatusServiceUnavailable)
		}},
		{"empty token", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":""}`))
		}},
		{"garbage body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
			srv := joinServer(t, tc.handler)
			cfg := joinConfig(t, api.URL, serverHostPort(t, srv))
			if err := RunJoin(context.Background(), cfg); err == nil {
				t.Fatal("expected RunJoin to fail")
			}
			assertAbsent(t, cfg.TokenOut)
			assertAbsent(t, cfg.FragmentOut)
		})
	}
}

func TestRunJoinConfigErrors(t *testing.T) {
	api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
	tests := []struct {
		name   string
		mutate func(*JoinConfig)
	}{
		{"platform required", func(c *JoinConfig) { c.Platform = "" }},
		{"server must be host:port", func(c *JoinConfig) { c.ServerAddr = "10.0.0.5" }},
		{"attestation-api down", func(c *JoinConfig) {
			c.AttestationAPIURL = "http://127.0.0.1:1"
			c.Timeout = time.Second
		}},
		{"timeout must be positive", func(c *JoinConfig) { c.Timeout = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := joinConfig(t, api.URL, "127.0.0.1:1")
			tc.mutate(&cfg)
			if err := RunJoin(context.Background(), cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestWriteStaged(t *testing.T) {
	dir := t.TempDir()
	cfg := JoinConfig{
		TokenOut:       filepath.Join(dir, "run", "join-token"),
		FragmentOut:    filepath.Join(dir, "config.yaml.d", "50-join.yaml"),
		SupervisorPort: 9345,
	}
	// Pre-create both outputs world-readable: os.WriteFile's perm applies only
	// on create, so a stale file would keep leaking the token.
	for _, p := range []string{cfg.TokenOut, cfg.FragmentOut} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeStaged(cfg, "2001:db8::1", "tok"); err != nil {
		t.Fatal(err)
	}
	assertMode(t, cfg.TokenOut, 0o600)
	assertMode(t, cfg.FragmentOut, 0o600)
	if token, err := os.ReadFile(cfg.TokenOut); err != nil {
		t.Fatal(err)
	} else if string(token) != "tok\n" {
		t.Errorf("token = %q, want the fresh value", token)
	}

	var frag rke2Fragment
	b, err := os.ReadFile(cfg.FragmentOut)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &frag); err != nil {
		t.Fatal(err)
	}
	if frag.Server != "https://[2001:db8::1]:9345" {
		t.Errorf("server = %q, want bracketed IPv6 URL", frag.Server)
	}
}

// TestPrepareTokenDir: the "must be tmpfs" invariant is enforced, not merely
// documented.
func TestPrepareTokenDir(t *testing.T) {
	t.Run("tmpfs accepted", func(t *testing.T) {
		if err := prepareTokenDir(filepath.Join(ramTempDir(t), "confos", "join-token")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("persistent storage refused", func(t *testing.T) {
		dir := t.TempDir()
		if fileutil.RequireRAMBacked(dir) == nil {
			t.Skipf("%s is RAM-backed; no on-disk path to reject", dir)
		}
		if err := prepareTokenDir(filepath.Join(dir, "join-token")); err == nil {
			t.Fatal("expected a token-out on persistent storage to be refused")
		}
	})
}

// waitForListen polls addr until it accepts a TCP connection or done yields.
func waitForListen(t *testing.T, addr string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case err := <-done:
			t.Fatalf("server exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never started accepting connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != want {
		t.Errorf("%s mode = %#o, want %#o", path, fi.Mode().Perm(), want)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists (err=%v), want absent", path, err)
	}
}
