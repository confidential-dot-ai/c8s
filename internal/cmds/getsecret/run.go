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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// config is everything the sidecar needs. The webhook renders all of it.
type config struct {
	sidecar.Config

	Secrets  []secretRequest
	OutDir   string
	FileMode string
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

	pins, err := cfg.ParsePins()
	if err != nil {
		return err
	}

	var values map[string][]byte
	err = sidecar.Retry(ctx, cfg.Config, "secret", func(ctx context.Context) error {
		var err error
		values, err = fetchAll(ctx, cfg, pins)
		return err
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

// fetchAll gets every secret in one pass. All-or-nothing: a partial set is not
// written, so a consumer never sees some of its secrets and waits forever for
// the rest.
func fetchAll(ctx context.Context, cfg config, pins ratls.Pins) (map[string][]byte, error) {
	client, pub, err := sidecar.NewClient(cfg.Config, pins)
	if err != nil {
		return nil, err
	}
	return fetchAllWith(ctx, cfg, client, pub, cfg.Endpoint())
}

// fetchAllWith is fetchAll once the client and the key it is bound to exist.
func fetchAllWith(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, endpoint string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		value, err := fetchOne(ctx, cfg, client, pub, endpoint, s.Path)
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
func fetchOne(ctx context.Context, cfg config, client *http.Client, pub crypto.PublicKey, endpoint, path string) ([]byte, error) {
	value, status, err := sidecar.Do(ctx, cfg.Config, client, pub, endpoint, http.MethodGet, path)
	switch {
	case err != nil && status != http.StatusNotFound:
		return nil, err
	case status == http.StatusOK:
		return value, nil
	}

	value, status, err = sidecar.Do(ctx, cfg.Config, client, pub, endpoint, http.MethodPost, path)
	switch {
	case status == http.StatusCreated:
		return value, nil
	case status == http.StatusInsufficientStorage:
		// The ceiling clears only on a CDS restart; the holder quota clears
		// whenever an operator moves a charge off this entry.
		var refusal *sidecar.StatusError
		if errors.As(err, &refusal) && refusal.Code == types.ErrorCodeSecretStoreFull {
			return nil, sidecar.Terminal(err)
		}
		return nil, err
	case status != http.StatusConflict:
		return nil, err
	}

	value, status, err = sidecar.Do(ctx, cfg.Config, client, pub, endpoint, http.MethodGet, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("created by another replica but not readable: %w", err)
	}
	return value, nil
}

// writeAll writes every value atomically (temp file then rename) so a consumer
// polling for a file never reads a torn one.
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
		if err := fileutil.WriteAtomic(dest, value, mode); err != nil {
			return fmt.Errorf("write %s: %w", dest, err)
		}
	}
	return nil
}

func parseFileMode(s string) (os.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(s, "%o", &mode); err != nil || mode == 0 || mode > 0o777 {
		return 0, fmt.Errorf("--file-mode %q must be an octal file mode like 0640", s)
	}
	return os.FileMode(mode), nil
}

func validate(cfg *config) error {
	if err := cfg.Validate(); err != nil {
		return err
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
	if _, err := parseFileMode(cfg.FileMode); err != nil {
		return err
	}
	return nil
}
