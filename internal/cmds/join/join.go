package join

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// maxTokenRespBytes caps the /join-token response read. The token is a few
// hundred bytes; anything near the cap is malformed.
const maxTokenRespBytes = 64 << 10

// JoinConfig is the join client configuration.
type JoinConfig struct {
	// ServerAddr is the join-release endpoint as host:port (e.g. "10.0.0.5:8444").
	ServerAddr string
	// AttestationAPIURL is the local attestation-api base URL, used both for
	// this node's client-cert quote and for verifying the server's quote.
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx").
	Platform string
	// TokenOut is where the received token is written (tmpfs; the token must
	// never touch persistent storage).
	TokenOut string
	// FragmentOut is the rke2 config drop-in to write (server + token-file).
	FragmentOut string
	// SupervisorPort is the rke2 supervisor port on the server node, used in
	// the fragment's server URL.
	SupervisorPort int
	// Timeout bounds each network step (own attestation, TLS verification
	// round trip, token fetch). One attempt per invocation; retries belong to
	// the systemd unit.
	Timeout time.Duration
}

// rke2Fragment is the config.yaml.d drop-in rke2-agent merges on start.
type rke2Fragment struct {
	Server    string `yaml:"server"`
	TokenFile string `yaml:"token-file"`
}

// RunJoin performs one attested join exchange: verify the server is a
// same-image TDX guest (RA-TLS + register comparison), present this node's
// own quote-bound client cert, fetch the token, and stage it for rke2-agent.
func RunJoin(ctx context.Context, cfg JoinConfig) error {
	cfg.Platform = ratls.NormalizePlatform(cfg.Platform)
	if cfg.Platform == "" {
		return fmt.Errorf("--platform is required (RA-TLS is mandatory for join)")
	}
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("--server must be host:port: %w", err)
	}

	api := attestationclient.NewClient(cfg.AttestationAPIURL)
	refsCtx, cancelRefs := context.WithTimeout(ctx, cfg.Timeout)
	own, err := ownRefs(refsCtx, api)
	cancelRefs()
	if err != nil {
		return err
	}

	// Client cert with an embedded quote bound to its own key: the server's
	// side of the mutual attestation.
	attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationAPIURL)
	tlsCfg, certMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Platform:   cfg.Platform,
		AttestFunc: attestFunc,
		Logger:     slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("build RA-TLS client config: %w", err)
	}
	// Replace ratls's delegated peer callback (which requires a VerifyPolicy
	// and checks MRTD only) with the full same-image check. The handshake
	// callback carries no context, so the verification round trip to the
	// local attestation-api gets its own bounded one.
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("join: server presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("join: parse server cert: %w", err)
		}
		vctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
		return verifyPeer(vctx, api, leaf, own)
	}

	warmCtx, cancelWarm := context.WithTimeout(ctx, cfg.Timeout)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("provision client cert: %w", err)
	}

	token, err := fetchToken(ctx, cfg, tlsCfg.Clone())
	if err != nil {
		return err
	}

	if err := writeStaged(cfg, host, token); err != nil {
		return err
	}
	slog.Info("joined: token staged", "server", cfg.ServerAddr, "token_file", cfg.TokenOut, "fragment", cfg.FragmentOut)
	return nil
}

// fetchToken performs the GET /join-token exchange over the mutually
// attested channel.
func fetchToken(ctx context.Context, cfg JoinConfig, tlsCfg *tls.Config) (string, error) {
	httpClient := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	url := "https://" + cfg.ServerAddr + "/join-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch join token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenRespBytes))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is server-controlled but the server is attested by now;
		// still, don't echo more than the status line needs.
		return "", fmt.Errorf("join-release returned %s", resp.Status)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if tr.Token == "" {
		return "", fmt.Errorf("join-release returned an empty token")
	}
	return tr.Token, nil
}

// writeStaged writes the token (tmpfs) and the rke2 config fragment. Order
// matters only for partial-failure cleanliness: the fragment references the
// token file, so the token lands first. A failed run is retried whole by the
// unit; both writes are idempotent overwrites.
func writeStaged(cfg JoinConfig, host, token string) error {
	for _, p := range []string{cfg.TokenOut, cfg.FragmentOut} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(p), err)
		}
	}
	if err := os.WriteFile(cfg.TokenOut, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("write token: %w", err)
	}

	frag, err := yaml.Marshal(rke2Fragment{
		Server:    "https://" + net.JoinHostPort(host, strconv.Itoa(cfg.SupervisorPort)),
		TokenFile: cfg.TokenOut,
	})
	if err != nil {
		return fmt.Errorf("marshal rke2 fragment: %w", err)
	}
	if err := os.WriteFile(cfg.FragmentOut, frag, 0o600); err != nil {
		return fmt.Errorf("write rke2 fragment: %w", err)
	}
	return nil
}
