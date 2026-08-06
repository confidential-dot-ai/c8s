package allowlist

import (
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
