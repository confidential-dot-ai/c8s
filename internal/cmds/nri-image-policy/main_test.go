package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStaticAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static-allowlist.json")
	doc := `{"schema":"c8s.allowlist/v1","digests":{"sha256:1111111111111111111111111111111111111111111111111111111111111111":"ghcr.io/x/a"},"workloads":{}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	al, digest, err := loadStaticAllowlist(path)
	if err != nil {
		t.Fatalf("loadStaticAllowlist: %v", err)
	}
	if len(al.Digests) != 1 || len(digest) != 64 {
		t.Fatalf("loadStaticAllowlist = %d digests, digest %q", len(al.Digests), digest)
	}
	if _, _, err := loadStaticAllowlist(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing baked policy must be fatal")
	}
}
