// Package cranetest installs a crane CLI stub on PATH for tests of
// crane-backed commands, so they run without a registry or the real binary.
package cranetest

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	// DigA is the digest the stub resolves every ordinary ref to.
	DigA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// DigB marks a missing manifest: `crane manifest` fails for refs
	// containing it.
	DigB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Install prepends a crane stub to PATH: digest resolves any ref to DigA
// (refs containing "unresolvable" fail with MANIFEST_UNKNOWN), config serves
// a fixed image config with Entrypoint, Cmd and Env (refs containing
// "badjson" serve garbage), and manifest fails for DigB refs.
func Install(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
cmd="$1"; ref="$2"
case "$cmd" in
digest)
  case "$ref" in
  *unresolvable*) echo "MANIFEST_UNKNOWN" >&2; exit 1 ;;
  *) echo "` + DigA + `" ;;
  esac ;;
config)
  case "$ref" in
  *badjson*) echo "not json" ;;
  *) echo '{"config":{"Entrypoint":["/bin/app"],"Cmd":["serve","--port=1"],"Env":["PATH=/usr/bin:/bin","APP_MODE=prod"]}}' ;;
  esac ;;
manifest)
  case "$ref" in
  *` + DigB + `*) exit 1 ;;
  *) exit 0 ;;
  esac ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "crane"), []byte(script), 0o755); err != nil {
		t.Fatalf("write crane stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
