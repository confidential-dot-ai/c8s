// Package crane wraps the crane CLI (github.com/google/go-containerregistry):
// digest resolution, image config, manifest existence, and the error shapes
// callers key behaviour on. crane handles registry auth, manifest lists, and
// the registry HTTP protocol.
package crane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Available reports whether the crane CLI is on PATH. Callers that can
// degrade (warn and continue) branch on this; callers that cannot use
// Require.
func Available() bool {
	_, err := exec.LookPath("crane")
	return err == nil
}

// Require fails with actionable guidance when the crane CLI is not on PATH,
// so a missing binary surfaces as an install hint rather than an opaque exec
// error from the first crane call.
func Require() error {
	if !Available() {
		return fmt.Errorf("this command needs the 'crane' CLI on PATH (github.com/google/go-containerregistry); install it and retry")
	}
	return nil
}

// Digest resolves an image reference to its registry digest via
// `crane digest <ref>`. The returned value is a bare "sha256:<hex>".
func Digest(ctx context.Context, ref string) (string, error) {
	out, err := exec.CommandContext(ctx, "crane", "digest", ref).Output()
	if err != nil {
		return "", craneError("digest", ref, err)
	}
	digest := strings.TrimSpace(string(out))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("crane digest %q returned unexpected value %q", ref, digest)
	}
	return digest, nil
}

// Config returns the parsed OCI image config for a reference via
// `crane config <ref>`, exposing the image's baked Entrypoint and Cmd.
func Config(ctx context.Context, ref string) (*ImageConfig, error) {
	out, err := exec.CommandContext(ctx, "crane", "config", ref).Output()
	if err != nil {
		return nil, craneError("config", ref, err)
	}
	var cfg ImageConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("parse crane config %q: %w", ref, err)
	}
	return &cfg, nil
}

// ManifestExists reports whether a specific digest is resolvable in its
// repository via `crane manifest <repo>@<digest>`.
func ManifestExists(ctx context.Context, ref string) error {
	if err := exec.CommandContext(ctx, "crane", "manifest", ref).Run(); err != nil {
		return craneError("manifest", ref, err)
	}
	return nil
}

// ImageConfig is the subset of an OCI image config the callers read.
type ImageConfig struct {
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"config"`
}

// IsNotFound reports whether a resolve error means the reference does not
// exist in the registry (as opposed to auth/network trouble). crane surfaces
// the registry's OCI error codes verbatim: MANIFEST_UNKNOWN for a missing
// tag, NAME_UNKNOWN for a missing repository. Matching them lets callers
// attach guidance only when the reference is genuinely absent — a 401 or a
// DNS failure gets the raw error instead.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "MANIFEST_UNKNOWN") || strings.Contains(msg, "NAME_UNKNOWN")
}

// craneError attaches the subcommand, reference, and captured stderr — the
// registry's own error text — to a failed crane invocation.
func craneError(sub, ref string, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("crane %s %q: %w: %s", sub, ref, err, strings.TrimSpace(string(ee.Stderr)))
	}
	return fmt.Errorf("crane %s %q: %w", sub, ref, err)
}
