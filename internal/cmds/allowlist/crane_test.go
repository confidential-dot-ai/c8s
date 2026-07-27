package allowlist

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// With crane off PATH, the crane-backed commands must fail with an actionable
// message rather than an opaque exec error from the first crane call.

func TestInspectImageRequiresCrane(t *testing.T) {
	t.Setenv("PATH", "")
	_, _, err := runCmd("inspect-image", "docker.io/library/busybox:latest")
	if err == nil || !strings.Contains(err.Error(), "crane") {
		t.Fatalf("expected a crane-not-found error, got %v", err)
	}
}

func TestLintOnlineRequiresCrane(t *testing.T) {
	f := filepath.Join(t.TempDir(), "al.json")
	if err := os.WriteFile(f, []byte(`{"schema":"c8s.allowlist/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	_, _, err := runCmd("lint", "--online", f)
	if err == nil || !strings.Contains(err.Error(), "crane") {
		t.Fatalf("expected a crane-not-found error, got %v", err)
	}
}

func TestCraneDigest(t *testing.T) {
	fakeCrane(t)
	got, err := craneDigest(context.Background(), "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("craneDigest: %v", err)
	}
	if got != digA {
		t.Fatalf("craneDigest = %q, want %q", got, digA)
	}
	if _, err := craneDigest(context.Background(), "registry.example.com/unresolvable:v1"); err == nil {
		t.Fatal("expected a resolve failure")
	}
}

func TestCraneConfig(t *testing.T) {
	fakeCrane(t)
	cfg, err := craneConfig(context.Background(), "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("craneConfig: %v", err)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/bin/app" {
		t.Fatalf("entrypoint = %v", cfg.Config.Entrypoint)
	}
	if len(cfg.Config.Cmd) != 2 || cfg.Config.Cmd[0] != "serve" || cfg.Config.Cmd[1] != "--port=1" {
		t.Fatalf("cmd = %v", cfg.Config.Cmd)
	}
	if _, err := craneConfig(context.Background(), "registry.example.com/badjson:v1"); err == nil || !strings.Contains(err.Error(), "parse crane config") {
		t.Fatalf("expected a config parse error, got %v", err)
	}
}

func TestCraneManifestExists(t *testing.T) {
	fakeCrane(t)
	if err := craneManifestExists(context.Background(), "registry.example.com/app@"+digA); err != nil {
		t.Fatalf("existing manifest must not error: %v", err)
	}
	if err := craneManifestExists(context.Background(), "registry.example.com/app@"+digB); err == nil {
		t.Fatal("expected a missing manifest to error")
	}
}

func TestLintOfflineDoesNotNeedCrane(t *testing.T) {
	f := filepath.Join(t.TempDir(), "al.json")
	if err := os.WriteFile(f, []byte(`{"schema":"c8s.allowlist/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if _, _, err := runCmd("lint", f); err != nil {
		t.Fatalf("offline lint must not require crane, got %v", err)
	}
}
