package nriimagepolicy

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticPolicyEnablesSandboxTokenSigner(t *testing.T) {
	cfg := config{
		Allowlist:      allowlistConfig{StaticPath: "/etc/c8s/static-allowlist.json"},
		WorkloadClaims: workloadClaimsConfig{AdvertiseHost: "10.0.0.1"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	signer, err := sandboxTokenSigner(&cfg, logger)
	if err != nil {
		t.Fatalf("sandboxTokenSigner: %v", err)
	}
	if signer == nil {
		t.Fatal("static policy disabled sandbox token signing")
	}
}

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
