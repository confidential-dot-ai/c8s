package crane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	digA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeCrane installs a crane stub on PATH: digest resolves any ref to digA
// (refs containing "unresolvable" fail), config serves a fixed image config
// (refs containing "badjson" serve garbage), and manifest fails for digB refs.
func fakeCrane(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
cmd="$1"; ref="$2"
case "$cmd" in
digest)
  case "$ref" in
  *unresolvable*) echo "MANIFEST_UNKNOWN" >&2; exit 1 ;;
  *) echo "` + digA + `" ;;
  esac ;;
config)
  case "$ref" in
  *badjson*) echo "not json" ;;
  *) echo '{"config":{"Entrypoint":["/bin/app"],"Cmd":["serve","--port=1"]}}' ;;
  esac ;;
manifest)
  case "$ref" in
  *` + digB + `*) exit 1 ;;
  *) exit 0 ;;
  esac ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "crane"), []byte(script), 0o755); err != nil {
		t.Fatalf("write crane stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestDigest(t *testing.T) {
	fakeCrane(t)
	got, err := Digest(context.Background(), "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != digA {
		t.Fatalf("Digest = %q, want %q", got, digA)
	}
	if _, err := Digest(context.Background(), "registry.example.com/unresolvable:v1"); err == nil {
		t.Fatal("expected a resolve failure")
	}
}

func TestConfig(t *testing.T) {
	fakeCrane(t)
	cfg, err := Config(context.Background(), "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/bin/app" {
		t.Fatalf("entrypoint = %v", cfg.Config.Entrypoint)
	}
	if len(cfg.Config.Cmd) != 2 || cfg.Config.Cmd[0] != "serve" || cfg.Config.Cmd[1] != "--port=1" {
		t.Fatalf("cmd = %v", cfg.Config.Cmd)
	}
	if _, err := Config(context.Background(), "registry.example.com/badjson:v1"); err == nil || !strings.Contains(err.Error(), "parse crane config") {
		t.Fatalf("expected a config parse error, got %v", err)
	}
}

func TestManifestExists(t *testing.T) {
	fakeCrane(t)
	if err := ManifestExists(context.Background(), "registry.example.com/app@"+digA); err != nil {
		t.Fatalf("existing manifest must not error: %v", err)
	}
	if err := ManifestExists(context.Background(), "registry.example.com/app@"+digB); err == nil {
		t.Fatal("expected a missing manifest to error")
	}
}

// IsNotFound keys caller guidance to the registry's own missing-reference
// error codes, so auth and network failures never masquerade as a missing
// reference.
func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "missing tag", err: errors.New("crane digest: MANIFEST_UNKNOWN: manifest unknown"), want: true},
		{name: "missing repository", err: errors.New("crane digest: NAME_UNKNOWN: repository name not known to registry"), want: true},
		{name: "auth failure", err: errors.New("crane digest: UNAUTHORIZED: authentication required"), want: false},
		{name: "network failure", err: errors.New("dial tcp: lookup ghcr.io: no such host"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Fatalf("IsNotFound(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}
