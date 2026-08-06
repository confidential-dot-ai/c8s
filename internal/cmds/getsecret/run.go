// Package getsecret implements the get-secret subcommand: the sidecar that
// fetches a workload's secrets from CDS and writes them into the pod.
//
// It runs as a native sidecar rather than an init container because CDS only
// releases once every main container is running — release is gated on the whole
// container set matching a workload entry, and an init container would be
// asking before its siblings exist (docs/secrets.md). So it starts alongside the
// workload, retries while the set completes, and writes when it does. The
// consumer must therefore tolerate the file appearing shortly after it starts.
package getsecret

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// inventoryEndpoint is the node-CVM endpoint the sandbox token is redeemed at.
// A package variable only so tests can point it at a socket they control;
// production always uses one of the two compiled paths, which is what stops a
// control-plane value redirecting the redemption to a rogue inventory
// (docs/getcert-workload-binding.md, Corner 5).
var inventoryEndpoint = workloadclaims.InventoryEndpoint

// config is everything the sidecar needs. The webhook renders all of it.
type config struct {
	CDSURL            string
	AttestationApiURL string
	Measurements      []string

	CertPath string
	KeyPath  string

	// WorkloadClaimsGuest selects the kata shape: the inventory is
	// policy-monitor inside the guest, reached on guest loopback rather than
	// the node-CVM socket, which a kata guest cannot mount.
	WorkloadClaimsGuest bool

	Secrets  []secretRequest
	OutDir   string
	FileMode string

	Attempts         int
	RetryInterval    time.Duration
	RequestTimeout   time.Duration
	InventoryTimeout time.Duration
}

// secretRequest is one NAME=/store/path pair: which secret to fetch and what to
// call the file it lands in.
type secretRequest struct {
	Name string
	Path string
}

// parseSecretSpec parses a NAME=/store/path pair. The name becomes a filename,
// so it may not contain a separator.
func parseSecretSpec(spec string) (secretRequest, error) {
	name, path, ok := strings.Cut(spec, "=")
	if !ok {
		return secretRequest{}, fmt.Errorf("secret %q must be NAME=/store/path", spec)
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return secretRequest{}, fmt.Errorf("secret name %q must be non-empty and not a path", name)
	}
	// Canonicalised with the same code CDS matches grants against, so a path
	// this sidecar accepts is one the server can answer for.
	canonical, err := pkgallowlist.CanonicalSecretPath(strings.TrimSpace(path))
	if err != nil {
		return secretRequest{}, fmt.Errorf("secret %q: %w", name, err)
	}
	return secretRequest{Name: name, Path: canonical}, nil
}

func run(cfg config) error {
	if err := validate(&cfg); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	measurements, err := ratls.ParseHexMeasurementsList(cfg.Measurements)
	if err != nil {
		return fmt.Errorf("--measurements: %w", err)
	}
	if len(measurements) == 0 {
		slog.Warn("--measurements empty: the CDS this sidecar hands its sandbox token to is not pinned to a launch measurement. UNSAFE outside development.")
	}

	values, err := fetchWithRetry(ctx, cfg, func(ctx context.Context) (map[string][]byte, error) {
		return fetchAll(ctx, cfg, measurements)
	})
	if err != nil {
		return err
	}
	if err := writeAll(cfg, values); err != nil {
		return err
	}
	slog.Info("secrets written", "count", len(values), "dir", cfg.OutDir)

	// A native sidecar that exits is restarted by the kubelet for the pod's
	// life, re-running the whole release check each time. Idling until the pod
	// is torn down leaves its status reflecting the workload rather than this
	// sidecar.
	<-ctx.Done()
	return nil
}

// fetchWithRetry gets every requested secret, retrying the whole set.
//
// Retrying is expected, not exceptional: until every main container is running
// the sandbox does not match its workload entry, so early attempts are denied
// by design. The bound turns a genuinely stuck release into a visible failure
// instead of an idle sidecar in a Running pod.
func fetchWithRetry(ctx context.Context, cfg config, fetch func(context.Context) (map[string][]byte, error)) (map[string][]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		values, err := fetch(ctx)
		if err == nil {
			return values, nil
		}
		lastErr = err
		if attempt == cfg.Attempts {
			break
		}
		slog.Info("secret not released yet; retrying",
			"attempt", attempt, "of", cfg.Attempts, "retry_in", cfg.RetryInterval, "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(cfg.RetryInterval):
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", cfg.Attempts, lastErr)
}

// fetchAll gets every secret in one pass. All-or-nothing: a partial set is not
// written, so a consumer never sees some of its secrets and waits forever for
// the rest.
func fetchAll(ctx context.Context, cfg config, measurements [][]byte) (map[string][]byte, error) {
	client, pub, err := newClient(cfg, measurements)
	if err != nil {
		return nil, err
	}
	return fetchAllWith(ctx, cfg, client, pub)
}

// fetchAllWith is fetchAll once the client and the key it is bound to exist.
func fetchAllWith(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey) (map[string][]byte, error) {
	out := make(map[string][]byte, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		value, err := fetchOne(ctx, cfg, client, pub, s.Path)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", s.Path, err)
		}
		out[s.Name] = value
	}
	return out, nil
}

// fetchOne reads a secret, creating it if the store holds nothing yet.
//
// A workload that starts and finds its path empty is the one that creates it,
// so 404 means "create". A 409 on that create means another replica won the
// race, and the value is read back rather than returned by the create.
func fetchOne(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, path string) ([]byte, error) {
	value, status, err := do(ctx, cfg, client, pub, http.MethodGet, path)
	switch {
	case err != nil && status != http.StatusNotFound:
		return nil, err
	case status == http.StatusOK:
		return value, nil
	}

	value, status, err = do(ctx, cfg, client, pub, http.MethodPost, path)
	switch {
	case status == http.StatusCreated:
		return value, nil
	case status != http.StatusConflict:
		return nil, err
	}

	value, status, err = do(ctx, cfg, client, pub, http.MethodGet, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("created by another replica but not readable: %w", err)
	}
	return value, nil
}

// do performs one secret request: a fresh challenge, a sandbox token bound to
// it and to this pod's leaf key, then the request itself. Both are single-use,
// so every call takes its own.
func do(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, method, path string) ([]byte, int, error) {
	challenge, err := fetchChallenge(ctx, cfg, client)
	if err != nil {
		return nil, 0, err
	}
	token, err := workloadclaims.FetchSandboxToken(ctx, cfg.endpoint(), cfg.InventoryTimeout, pub, challenge)
	if err != nil {
		return nil, 0, fmt.Errorf("redeem sandbox token: %w", err)
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, 0, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, cfg.CDSURL+"/secrets"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set(secrets.ChallengeHeader, base64.StdEncoding.EncodeToString(challenge))
	req.Header.Set("Authorization", secrets.AuthScheme+base64.StdEncoding.EncodeToString(tokenJSON))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decode secret response: %w", err)
		}
		value, err := base64.StdEncoding.DecodeString(body.Value)
		if err != nil {
			return nil, resp.StatusCode, fmt.Errorf("secret value is not base64: %w", err)
		}
		return value, resp.StatusCode, nil
	default:
		// The body is deliberately opaque; the reason is in the CDS log.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(detail)))
	}
}

// endpoint is the compiled inventory endpoint for this sidecar's shape. The
// flag selects between two baked values, never an address.
func (c config) endpoint() string {
	if c.WorkloadClaimsGuest {
		return workloadclaims.GuestInventoryEndpoint()
	}
	return inventoryEndpoint()
}

func fetchChallenge(ctx context.Context, cfg config, client *http.Client) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.CDSURL+secrets.ChallengeRoute, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch challenge: %s", resp.Status)
	}
	var out types.ChallengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(out.Challenge)
	if err != nil {
		return nil, fmt.Errorf("challenge is not base64: %w", err)
	}
	return challenge, nil
}

// leafProvider presents the pod's CDS-issued leaf as the client certificate.
// It reloads from disk on each provision, so a renewal written by the cert
// sidecar is picked up without restarting this one.
type leafProvider struct{ certPath, keyPath string }

func (p leafProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	cert, err := tls.LoadX509KeyPair(p.certPath, p.keyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("load leaf %s: %w", p.certPath, err)
	}
	return &cert, time.Hour, nil
}

// newClient builds the mTLS client to CDS and returns the leaf's public key,
// which the sandbox token is bound to.
func newClient(cfg config, measurements [][]byte) (*http.Client, crypto.PublicKey, error) {
	provider := leafProvider{certPath: cfg.CertPath, keyPath: cfg.KeyPath}
	leaf, _, err := provider.Provision(context.Background())
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf: %w", err)
	}
	tlsCfg, _, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:       &ratls.VerifyPolicy{Measurements: measurements, AttestationApiURL: cfg.AttestationApiURL},
		CertProvider: provider,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build CDS client: %w", err)
	}
	return &http.Client{
		Timeout:   cfg.RequestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, parsed.PublicKey, nil
}

// writeAll writes every value, then verifies nothing was left behind. Each
// write is atomic (temp file then rename) so a consumer polling for the file
// never reads a torn one.
func writeAll(cfg config, values map[string][]byte) error {
	mode, err := parseFileMode(cfg.FileMode)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", cfg.OutDir, err)
	}
	for name, value := range values {
		dest := filepath.Join(cfg.OutDir, name)
		tmp, err := os.CreateTemp(cfg.OutDir, "."+name+".*")
		if err != nil {
			return fmt.Errorf("create temp for %s: %w", dest, err)
		}
		if err := writeAndClose(tmp, value, mode); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("write %s: %w", dest, err)
		}
		if err := os.Rename(tmp.Name(), dest); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("rename into %s: %w", dest, err)
		}
	}
	return nil
}

func writeAndClose(f *os.File, value []byte, mode os.FileMode) error {
	// Chmod before the content lands, so the value is never briefly readable
	// under the temp file's default mode.
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(value); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func parseFileMode(s string) (os.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(s, "%o", &mode); err != nil || mode == 0 || mode > 0o777 {
		return 0, fmt.Errorf("--file-mode %q must be an octal file mode like 0640", s)
	}
	return os.FileMode(mode), nil
}

func validate(cfg *config) error {
	if cfg.CDSURL == "" {
		return fmt.Errorf("--cds-url is required")
	}
	cfg.CDSURL = strings.TrimRight(cfg.CDSURL, "/")
	if !strings.HasPrefix(cfg.CDSURL, "https://") {
		return fmt.Errorf("--cds-url must be https (RA-TLS)")
	}
	if cfg.AttestationApiURL == "" {
		return fmt.Errorf("--attestation-api-url is required to verify CDS")
	}
	if len(cfg.Secrets) == 0 {
		return fmt.Errorf("at least one --secret NAME=/store/path is required")
	}
	seen := map[string]bool{}
	for _, s := range cfg.Secrets {
		if seen[s.Name] {
			return fmt.Errorf("--secret name %q is repeated; each names a distinct file", s.Name)
		}
		seen[s.Name] = true
	}
	if cfg.Attempts <= 0 {
		return fmt.Errorf("--attempts must be positive")
	}
	if cfg.RetryInterval <= 0 || cfg.RequestTimeout <= 0 || cfg.InventoryTimeout <= 0 {
		return fmt.Errorf("--retry-interval, --request-timeout and --inventory-timeout must be positive")
	}
	if _, err := parseFileMode(cfg.FileMode); err != nil {
		return err
	}
	return nil
}
