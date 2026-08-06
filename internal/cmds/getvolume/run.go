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

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volumed"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// config is everything the sidecar needs. The webhook renders all of it.
type config struct {
	sidecar.Config

	Volumes []volumeRequest
	// SocketDir holds volumed's socket, as this pod sees it. Unused under
	// WorkloadClaimsGuest, where volumed is in the guest and there is no
	// filesystem shared with it.
	SocketDir string
}

// volumeRequest is one NAME=/store/path pair: which volume to open and where
// its key blob lives in the store.
type volumeRequest struct {
	Name string
	Path string
}

// parseVolumeSpec parses a NAME=/store/path pair. The name selects the device
// by serial and names the Kubernetes volume the plaintext is mounted into, so
// it must be a DNS-1123 label short enough for a disk serial.
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

	measurements, err := cfg.ParseMeasurements()
	if err != nil {
		return err
	}

	if err := sidecar.Retry(ctx, cfg.Config, "volume", func(ctx context.Context) error {
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

// openAll fetches and opens every requested volume in one pass. The daemon is
// idempotent for a repeated identical request, so a pass that fails partway is
// safe to run again.
func openAll(ctx context.Context, cfg config, measurements [][]byte) error {
	client, pub, err := sidecar.NewClient(cfg.Config, measurements)
	if err != nil {
		return err
	}
	daemon, base := daemonClient(cfg)
	return openAllWith(ctx, cfg, client, pub, daemon, base)
}

// openAllWith is openAll once the clients exist.
func openAllWith(ctx context.Context, cfg config, cds *http.Client, pub crypto.PublicKey, daemon *http.Client, daemonBase string) error {
	for _, v := range cfg.Volumes {
		blob, err := fetchBlob(ctx, cfg, cds, pub, v.Path)
		if err != nil {
			return fmt.Errorf("volume %s: %w", v.Name, err)
		}
		if err := openOne(ctx, cfg, daemon, daemonBase, v.Name, blob); err != nil {
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
	value, _, err := sidecar.Do(ctx, cfg.Config, client, pub, http.MethodGet, path)
	if err != nil {
		return volume.Blob{}, err
	}
	return volume.DecodeBlob(value)
}

// openOne hands the blob to the node daemon, which resolves this pod from the
// socket's peer credentials and mounts the volume into it.
func openOne(ctx context.Context, cfg config, daemon *http.Client, daemonBase, name string, blob volume.Blob) error {
	body, err := json.Marshal(volumed.OpenRequest{Name: name, Blob: blob})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, daemonBase+volumed.VolumePath, bytes.NewReader(body))
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

// daemonClient reaches volumed and returns the base URL to post to: the socket
// the webhook mounts into this sidecar on node-CVM, or the guest's compiled
// loopback address under kata, where volumed is in this VM and there is no
// shared filesystem. Both are compiled; the flag selects a shape, not an
// address.
func daemonClient(cfg config) (*http.Client, string) {
	if cfg.WorkloadClaimsGuest {
		// Fresh Transport, so Proxy stays nil: no HTTP_PROXY can interpose on
		// the key blob's trip to the daemon.
		return &http.Client{Transport: &http.Transport{}}, volumed.GuestEndpoint()
	}
	sock := filepath.Join(cfg.SocketDir, volumed.SocketName)
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
		// The host is ignored on a unix transport; the URL only has to parse.
	}}, "http://volumed"
}

func validate(cfg *config) error {
	if err := cfg.Config.Validate(); err != nil {
		return err
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
	// Under kata volumed is in the guest on a compiled loopback address, so
	// there is no socket directory to require.
	if cfg.SocketDir == "" && !cfg.WorkloadClaimsGuest {
		return fmt.Errorf("--socket-dir is required")
	}
	return nil
}
