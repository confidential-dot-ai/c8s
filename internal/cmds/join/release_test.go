package join

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testHandler builds a releaseHandler over a fake attestation-api and a token
// path inside a temp dir (file not written unless token != "").
func testHandler(t *testing.T, api *fakeAPI, token string) *releaseHandler {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "agent-token")
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
		verifySlots:   make(chan struct{}, maxConcurrentVerifications),
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
		h := testHandler(t, okAPI(t), "K10cafe::node:secret\n")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
		}
		var resp tokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Token != "K10cafe::node:secret" {
			t.Errorf("token = %q, want trimmed staged token", resp.Token)
		}
	})

	t.Run("policy mismatch denied", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyResp(digestB, rtmr1A, rtmr2A, true, true)))
		h := testHandler(t, api, "K10cafe::node:secret")
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
		if err := os.WriteFile(h.tokenPath, []byte("K10cafe::node:late-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec := doTLS(h, http.MethodGet, "/join-token", leaf); rec.Code != http.StatusOK {
			t.Fatalf("second status = %d, want 200", rec.Code)
		}
	})

	t.Run("server token is never released", func(t *testing.T) {
		h := testHandler(t, okAPI(t), "K10cafe::server:secret")
		rec := doTLS(h, http.MethodGet, "/join-token", []*x509.Certificate{attestedLeaf(t, tdxEnvelope)})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
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

func TestReleaseHandlerBoundsConcurrentVerification(t *testing.T) {
	entered := make(chan struct{}, maxConcurrentVerifications)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }

	api := newFakeAPI(t, func(int, types.VerifyRequest) types.VerifyResponse {
		entered <- struct{}{}
		<-release
		return verifyResp(digestA, rtmr1A, rtmr2A, true, true)
	})
	t.Cleanup(unblock)
	h := testHandler(t, api, "K10cafe::node:secret")
	leaf := []*x509.Certificate{attestedLeaf(t, tdxEnvelope)}

	var wg sync.WaitGroup
	statuses := make(chan int, maxConcurrentVerifications)
	for range maxConcurrentVerifications {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- doTLS(h, http.MethodGet, "/join-token", leaf).Code
		}()
	}

	for range maxConcurrentVerifications {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("verification requests did not reach the configured limit")
		}
	}

	overflow := doTLS(h, http.MethodGet, "/join-token", leaf)
	if overflow.Code != http.StatusServiceUnavailable {
		t.Errorf("overflow status = %d, want 503", overflow.Code)
	}
	if got := api.verifyCalls.Load(); got != maxConcurrentVerifications {
		t.Errorf("verify calls = %d, want %d", got, maxConcurrentVerifications)
	}

	unblock()
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Errorf("admitted request status = %d, want 200", status)
		}
	}
}

func TestIsSecureAgentToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "agent token", token: "K10cafe::node:secret", want: true},
		{name: "server token", token: "K10cafe::server:secret", want: false},
		{name: "node marker inside server secret", token: "K10cafe::server:secret::node:forged", want: false},
		{name: "missing secret", token: "K10cafe::node:", want: false},
		{name: "short token", token: "secret", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSecureAgentToken(tt.token); got != tt.want {
				t.Errorf("isSecureAgentToken(%q) = %t, want %t", tt.token, got, tt.want)
			}
		})
	}
}

// releaseConfig returns a ReleaseConfig RunRelease can fully start from.
func releaseConfig(t *testing.T) ReleaseConfig {
	t.Helper()
	api := newFakeAPI(t, staticVerify(verifyResp(digestA, rtmr1A, rtmr2A, true, true)))
	return ReleaseConfig{
		ListenAddr:        "127.0.0.1:0",
		AttestationAPIURL: api.URL,
		Platform:          "tdx",
		TokenPath:         filepath.Join(t.TempDir(), "agent-token"),
		VerifyTimeout:     5 * time.Second,
	}
}

func TestRunReleaseStartupErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(t *testing.T) ReleaseConfig
	}{
		{"platform required", func(t *testing.T) ReleaseConfig { return ReleaseConfig{Platform: ""} }},
		{"verify-timeout must be positive", func(t *testing.T) ReleaseConfig {
			cfg := releaseConfig(t)
			cfg.VerifyTimeout = 0
			return cfg
		}},
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

// probeCert builds a self-signed tls.Certificate the readiness probe presents
// as its client cert. The handler denies it (no RA-TLS extension); any HTTP
// response at all proves the server is accepting requests.
func probeCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestRunReleaseServesAndShutsDown(t *testing.T) {
	cfg := releaseConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg.ListenAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRelease(ctx, cfg, ln) }()

	// The injected listener is bound before runRelease starts, so a raw TCP
	// dial succeeds (accept backlog) while the startup attestation ladder is
	// still running and cancel would race it. Probe with a full HTTPS request
	// instead: a response only comes back once ServeTLS is accepting.
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{probeCert(t)},
		}},
	}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get("https://" + cfg.ListenAddr + "/join-token")
		if err == nil {
			resp.Body.Close()
			// The serving cert's validity window is the replay bound for a
			// stolen leaf key; pin it so a TTL change can't widen it silently.
			leaf := resp.TLS.PeerCertificates[0]
			if window := leaf.NotAfter.Sub(leaf.NotBefore); window > releaseServerCertTTL+time.Minute {
				t.Errorf("serving cert validity window = %s, want <= %s", window, releaseServerCertTTL)
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("RunRelease exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never answered a request: %v", err)
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
