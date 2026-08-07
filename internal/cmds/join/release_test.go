package join

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
)

// testHandler builds a releaseHandler over a fake attestation-api and a token
// path inside a temp dir (file not written unless token != "").
func testHandler(t *testing.T, api *fakeAPI, token string) *releaseHandler {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "node-token")
	if token != "" {
		if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &releaseHandler{
		api:           attestationclient.NewClient(api.URL),
		own:           mustRefs(t, digestA, rtmr1A, rtmr2A),
		tokenPath:     tokenPath,
		verifyTimeout: 5 * time.Second,
		logger:        slog.Default(),
	}
}

// doTLS runs a request through the handler with the given peer certs attached
// as TLS state.
func doTLS(h http.Handler, method, path string, peers []*x509.Certificate) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: peers}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReleaseHandler(t *testing.T) {
	okAPI := func(t *testing.T) *fakeAPI {
		return newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
	}

	t.Run("attested same-image peer gets the token", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "K10cafe::server:secret\n")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
		}
		var resp tokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Token != "K10cafe::server:secret" {
			t.Errorf("token = %q, want trimmed staged token", resp.Token)
		}
	})

	t.Run("policy mismatch denied", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestB, rtmr1A, rtmr2A, true, true)))
		h := testHandler(t, api, "K10cafe::server:secret")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("no client certificate denied", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodGet, "/join-token", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("unattested certificate denied", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{plainLeaf(t)})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("token not on disk yet", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})

	t.Run("empty token file is not ready", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "\n")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})

	t.Run("token appearing later is served without restart", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "")
		leaf := []*x509.Certificate{attestedLeaf(t, tdxEnvelope)}
		if rec := doTLS(h, http.MethodGet, "/join-token", leaf); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("first status = %d, want 503", rec.Code)
		}
		if err := os.WriteFile(h.tokenPath, []byte("late-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec := doTLS(h, http.MethodGet, "/join-token", leaf); rec.Code != http.StatusOK {
			t.Fatalf("second status = %d, want 200", rec.Code)
		}
	})

	t.Run("wrong path", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodGet, "/release-credential", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "tok")
		rec := doTLS(h, http.MethodPost, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})
}

// releaseConfig returns a ReleaseConfig RunRelease can fully start from.
func releaseConfig(t *testing.T) ReleaseConfig {
	t.Helper()
	api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
	return ReleaseConfig{
		ListenAddr:        "127.0.0.1:0",
		AttestationAPIURL: api.URL,
		Platform:          "tdx",
		TokenPath:         filepath.Join(t.TempDir(), "node-token"),
		VerifyTimeout:     5 * time.Second,
	}
}

func TestRunReleaseStartupErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(t *testing.T) ReleaseConfig
	}{
		{"platform required", func(t *testing.T) ReleaseConfig { return ReleaseConfig{Platform: ""} }},
		{"attestation-api down at own-refs", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.AttestationAPIURL = "http://127.0.0.1:1"
			return cfg
		}},
		{"own evidence fails verification", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.AttestationAPIURL = newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, false, true))).URL
			return cfg
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := RunRelease(context.Background(), tc.cfg(t)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestRunReleaseServesAndShutsDown(t *testing.T) {
	cfg := releaseConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenAddr = ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunRelease(ctx, cfg) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", cfg.ListenAddr, time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("RunRelease exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never started accepting connections")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunRelease after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunRelease did not return after context cancel")
	}
}

func TestRunReleaseListenError(t *testing.T) {
	cfg := releaseConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg.ListenAddr = ln.Addr().String() // already taken

	done := make(chan error, 1)
	go func() { done <- RunRelease(context.Background(), cfg) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected bind error, got nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunRelease did not surface the bind error")
	}
}
