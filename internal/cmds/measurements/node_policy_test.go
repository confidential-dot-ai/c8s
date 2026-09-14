package measurements

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLintAcceptsCompleteNodePolicy(t *testing.T) {
	cmd := newLintCmd()
	out := new(strings.Builder)
	cmd.SetOut(out)
	cmd.SetArgs([]string{filepath.Join("..", "..", "..", "pkg", "measurements", "testdata", "node-identities.json")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("valid image/operator-key policy rejected: %v", err)
	}
	if !strings.Contains(out.String(), "ok: tdx") {
		t.Fatalf("lint did not inspect the node policy: %s", out)
	}
}
