package join

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	// maxConcurrentConns caps accepted sockets and protects the HTTP server
	// from connection-level resource exhaustion.
	maxConcurrentConns = 64
	// maxConcurrentVerifications independently caps expensive attestation-api
	// calls. A single HTTP/2 connection can carry many concurrent requests, so
	// the listener limit alone is not an admission bound.
	maxConcurrentVerifications = 64
)

// ReleaseConfig is the join-release service configuration.
type ReleaseConfig struct {
	// ListenAddr is the HTTPS bind address (e.g. ":8444").
	ListenAddr string
	// AttestationAPIURL is the local attestation-api base URL, used both for
	// the RA-TLS serving cert's quote and for verifying callers' quotes.
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx").
	Platform string
	// TokenPath is the agent-only rke2 join token file (the full-format
	// K10<ca-hash>::node:... token rke2-server writes once initialised).
	TokenPath string
	// VerifyTimeout bounds the per-request peer verification round trip to
	// the attestation-api.
	VerifyTimeout time.Duration
}

// RunRelease serves the RA-TLS-protected /join-token endpoint. It blocks
// until ctx is done.
//
// Startup order matters for the trust story:
//  1. ownRefs: verify our own evidence and pin the same-image policy to it.
//     Fails closed if the local attestation stack is broken.
//  2. serve over an RA-TLS config that REQUIRES a client cert, so every
//     request carries the evidence the handler verifies.
func RunRelease(ctx context.Context, cfg ReleaseConfig) error {
	return runRelease(ctx, cfg, nil)
}

// runRelease serves on ln when non-nil (test injection); nil binds
// cfg.ListenAddr after the attestation ladder, never before policy is pinned.
func runRelease(ctx context.Context, cfg ReleaseConfig, ln net.Listener) error {
	// RA-TLS is mandatory: joining agents verify this endpoint's serving
	// quote before presenting their own evidence, so a plain-TLS listener
	// (empty platform in the ratls package) must never come up.
	cfg.Platform = ratls.NormalizePlatform(cfg.Platform)
	if cfg.Platform == "" {
		return fmt.Errorf("--platform is required (RA-TLS is mandatory for join release)")
	}
	// Non-positive: every request's verification context is already expired,
	// so the service comes up healthy and denies the entire cluster.
	if cfg.VerifyTimeout <= 0 {
		return fmt.Errorf("--verify-timeout must be positive (got %s)", cfg.VerifyTimeout)
	}

	api := attestationclient.NewClient(cfg.AttestationAPIURL)
	refsCtx, cancelRefs := context.WithTimeout(ctx, 30*time.Second)
	own, err := ownRefs(refsCtx, api)
	cancelRefs()
	if err != nil {
		return err
	}

	handler := &releaseHandler{
		api:           api,
		own:           own,
		tokenPath:     cfg.TokenPath,
		verifyTimeout: cfg.VerifyTimeout,
		verifySlots:   make(chan struct{}, maxConcurrentVerifications),
		logger:        slog.Default(),
	}

	attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationAPIURL)
	tlsCfg, certMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   cfg.Platform,
		AttestFunc: attestFunc,
		Logger:     slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("build RA-TLS config: %w", err)
	}
	// Demand a client cert at the TLS layer; verification lives in the
	// handler (verifyPeer) so the whole policy is one auditable path rather
	// than split between a TLS callback and the handler.
	tlsCfg.ClientAuth = tls.RequireAnyClientCert

	warmCtx, cancelWarm := context.WithTimeout(ctx, 30*time.Second)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("warm up RA-TLS serving cert: %w", err)
	}

	if ln == nil {
		var lnErr error
		ln, lnErr = net.Listen("tcp", cfg.ListenAddr)
		if lnErr != nil {
			return fmt.Errorf("listen %s: %w", cfg.ListenAddr, lnErr)
		}
	}

	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		// A slow reader or parked keep-alive must not hold a goroutine open.
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeTLS(netutil.LimitListener(ln, maxConcurrentConns), "", "")
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// tokenResponse is the /join-token response body.
type tokenResponse struct {
	Token string `json:"token"`
}

type releaseHandler struct {
	api           attestationclient.Client
	own           imageRefs
	tokenPath     string
	verifyTimeout time.Duration
	verifySlots   chan struct{}
	logger        *slog.Logger
}

func (h *releaseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/join-token" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// RequireAnyClientCert makes this unreachable over TLS; kept so a
		// misconfigured server can never release without evidence.
		h.logger.Warn("join denied: no client certificate", "remote", r.RemoteAddr)
		http.Error(w, "client certificate required", http.StatusForbidden)
		return
	}

	select {
	case h.verifySlots <- struct{}{}:
		defer func() { <-h.verifySlots }()
	default:
		h.logger.Warn("join delayed: verification capacity exhausted", "remote", r.RemoteAddr)
		http.Error(w, "join verification busy", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.verifyTimeout)
	defer cancel()
	if err := verifyPeer(ctx, h.api, r.TLS.PeerCertificates[0], h.own); err != nil {
		h.logger.Warn("join denied", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "join denied", http.StatusForbidden)
		return
	}

	// Read per request, no caching: the file appears only once rke2-server
	// has initialised, and agents retry on 503 until then.
	token, err := os.ReadFile(h.tokenPath)
	trimmed := strings.TrimSpace(string(token))
	if err != nil || trimmed == "" {
		h.logger.Warn("join token not ready", "remote", r.RemoteAddr, "path", h.tokenPath, "err", err)
		http.Error(w, "join token not ready", http.StatusServiceUnavailable)
		return
	}
	if !isSecureAgentToken(trimmed) {
		// INVARIANT: the admission endpoint must never release a credential
		// that can add an RKE2 server/control-plane node.
		h.logger.Error("join token has unexpected role", "path", h.tokenPath)
		http.Error(w, "join token not ready", http.StatusServiceUnavailable)
		return
	}

	h.logger.Info("join token released",
		"remote", r.RemoteAddr,
		"launch_digest", hex.EncodeToString(h.own.launchDigest))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResponse{Token: trimmed}); err != nil {
		h.logger.Warn("write response", "remote", r.RemoteAddr, "err", err)
	}
}

func isSecureAgentToken(token string) bool {
	// RKE2 names the agent-only basic-auth identity "node"; the privileged
	// server token uses the distinct "server" identity.
	caHash, credentials, ok := strings.Cut(token, "::")
	if !ok || !strings.HasPrefix(caHash, "K10") || len(caHash) == len("K10") || strings.ContainsRune(caHash, ':') {
		return false
	}
	username, secret, ok := strings.Cut(credentials, ":")
	return ok && username == "node" && secret != ""
}
