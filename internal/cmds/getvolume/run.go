// Package getvolume implements the get-volume subcommand: the sidecar that
// fetches a volume's key blob from CDS and hands it to the node's volumed,
// which opens the device and mounts it into this pod.
//
// It runs as a native sidecar rather than an init container for the same reason
// get-secret does: CDS only releases once every main container is running, so an
// init container would be asking before its siblings exist (docs/secrets.md).
// The volume therefore appears shortly after the workload starts, and a
// consumer must wait for it.
package getvolume

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volumed"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// inventoryEndpoint is where the sandbox token is redeemed. A package variable
// only so tests can point it at a socket they control; production always uses
// the compiled path, which is what stops a control-plane value redirecting the
// redemption to a rogue inventory (docs/getcert-workload-binding.md, Corner 5).
var inventoryEndpoint = workloadclaims.InventoryEndpoint

// config is everything the sidecar needs. The webhook renders all of it.
type config struct {
	CDSURL            string
	AttestationApiURL string
	Measurements      []string

	CertPath string
	KeyPath  string

	Volumes []volumeRequest
	// SocketDir holds volumed's socket, as this pod sees it.
	SocketDir string

	Attempts         int
	RetryInterval    time.Duration
	RequestTimeout   time.Duration
	InventoryTimeout time.Duration
}

// volumeRequest is one NAME=/store/path pair: which volume to open and where
// its key blob lives in the store.
type volumeRequest struct {
	Name string
	Path string
}

// parseVolumeSpec parses a NAME=/store/path pair. The name selects the device
// by serial and names the Kubernetes volume the plaintext is mounted into, so
// it must be a DNS-1123 label short enough for a virtio serial.
func parseVolumeSpec(spec string) (volumeRequest, error) {
	name, path, ok := strings.Cut(spec, "=")
	if !ok {
		return volumeRequest{}, fmt.Errorf("volume %q must be NAME=/store/path", spec)
	}
	name = strings.TrimSpace(name)
	if err := volumed.ValidVolumeName(name); err != nil {
		return volumeRequest{}, err
	}
	// Canonicalised with the same code CDS matches grants against, so a path
	// this sidecar accepts is one the server can answer for.
	canonical, err := pkgallowlist.CanonicalSecretPath(strings.TrimSpace(path))
	if err != nil {
		return volumeRequest{}, fmt.Errorf("volume %q: %w", name, err)
	}
	return volumeRequest{Name: name, Path: canonical}, nil
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

	if err := openWithRetry(ctx, cfg, func(ctx context.Context) error {
		return openAll(ctx, cfg, measurements)
	}); err != nil {
		return err
	}
	slog.Info("volumes opened", "count", len(cfg.Volumes))

	// A native sidecar that exits is restarted by the kubelet for the pod's
	// life, re-running the whole release check each time. Idling until the pod
	// is torn down leaves its status reflecting the workload rather than this
	// sidecar.
	<-ctx.Done()
	return nil
}

// openWithRetry runs one whole pass at a time, retrying the set.
//
// Retrying is expected, not exceptional: until every main container is running
// the sandbox does not match its workload entry, so early attempts are denied
// by design. The bound turns a genuinely stuck release into a visible failure
// instead of an idle sidecar in a Running pod.
func openWithRetry(ctx context.Context, cfg config, attempt func(context.Context) error) error {
	var lastErr error
	for n := 1; n <= cfg.Attempts; n++ {
		err := attempt(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if n == cfg.Attempts {
			// The last attempt's error is the one that matters: log it at
			// ERROR so a stuck release shows its real cause in the sidecar's
			// own log, not just the generic per-attempt INFO line.
			slog.Error("volume release failed on the final attempt",
				"attempt", n, "of", cfg.Attempts, "error", err)
			break
		}
		slog.Info("volume not released yet; retrying",
			"attempt", n, "of", cfg.Attempts, "retry_in", cfg.RetryInterval, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.RetryInterval):
		}
	}
	return fmt.Errorf("giving up after %d attempts: %w", cfg.Attempts, lastErr)
}

// openAll fetches and opens every requested volume in one pass. The daemon is
// idempotent for a repeated identical request, so a pass that fails partway is
// safe to run again.
func openAll(ctx context.Context, cfg config, measurements [][]byte) error {
	client, pub, err := newClient(cfg, measurements)
	if err != nil {
		return err
	}
	return openAllWith(ctx, cfg, client, pub, daemonClient(cfg.SocketDir))
}

// openAllWith is openAll once the clients exist.
func openAllWith(ctx context.Context, cfg config, cds *http.Client, pub crypto.PublicKey, daemon *http.Client) error {
	for _, v := range cfg.Volumes {
		blob, err := fetchBlob(ctx, cfg, cds, pub, v.Path)
		if err != nil {
			return fmt.Errorf("volume %s: %w", v.Name, err)
		}
		if err := openOne(ctx, cfg, daemon, v.Name, blob); err != nil {
			return fmt.Errorf("volume %s: %w", v.Name, err)
		}
	}
	return nil
}

// fetchBlob reads one volume's key blob from the store.
//
// GET only. get-secret creates a value when the store holds none, because the
// first pod of a workload to ask is the one that defines it. A volume key is
// never minted: the operator put it there with `c8s volume create`, and a POST
// here would squat the path with random bytes that decrypt nothing, leaving the
// real key unwritable behind a 409.
func fetchBlob(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, path string) (volume.Blob, error) {
	value, _, err := do(ctx, cfg, client, pub, path)
	if err != nil {
		return volume.Blob{}, err
	}
	return volume.DecodeBlob(value)
}

// do performs one store read: a fresh challenge, a sandbox token bound to it
// and to this pod's leaf key, then the request. Both are single-use, so every
// call takes its own.
func do(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, path string) ([]byte, int, error) {
	challenge, err := fetchChallenge(ctx, cfg, client)
	if err != nil {
		return nil, 0, err
	}
	token, err := workloadclaims.FetchSandboxToken(ctx, inventoryEndpoint(), cfg.InventoryTimeout, pub, challenge)
	if err != nil {
		return nil, 0, fmt.Errorf("redeem sandbox token: %w", err)
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, 0, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, cfg.CDSURL+"/secrets"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set(secrets.ChallengeHeader, base64.StdEncoding.EncodeToString(challenge))
	req.Header.Set("Authorization", secrets.AuthScheme+base64.StdEncoding.EncodeToString(tokenJSON))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The body is deliberately opaque; the reason is in the CDS log.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, resp.StatusCode, fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(detail)))
	}
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
}

// openOne hands the blob to the node daemon, which resolves this pod from the
// socket's peer credentials and mounts the volume into it.
func openOne(ctx context.Context, cfg config, daemon *http.Client, name string, blob volume.Blob) error {
	body, err := json.Marshal(volumed.OpenRequest{Name: name, Blob: blob})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	// The host is ignored on a unix transport; it only has to be a valid URL.
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "http://volumed"+volumed.VolumePath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := daemon.Do(req)
	if err != nil {
		return fmt.Errorf("open volume: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("open volume: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

// daemonClient dials volumed's socket in the inventory socket directory the
// webhook mounts into this sidecar.
func daemonClient(socketDir string) *http.Client {
	sock := filepath.Join(socketDir, volumed.SocketName)
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
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
	if len(cfg.Volumes) == 0 {
		return fmt.Errorf("at least one --volume NAME=/store/path is required")
	}
	seen := map[string]bool{}
	for _, v := range cfg.Volumes {
		if seen[v.Name] {
			return fmt.Errorf("--volume name %q is repeated; each names a distinct device", v.Name)
		}
		seen[v.Name] = true
	}
	if cfg.SocketDir == "" {
		return fmt.Errorf("--socket-dir is required")
	}
	if cfg.Attempts <= 0 {
		return fmt.Errorf("--attempts must be positive")
	}
	if cfg.RetryInterval <= 0 || cfg.RequestTimeout <= 0 || cfg.InventoryTimeout <= 0 {
		return fmt.Errorf("--retry-interval, --request-timeout and --inventory-timeout must be positive")
	}
	return nil
}
