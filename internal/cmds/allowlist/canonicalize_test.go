package allowlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalizeCmd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	input := `{
  "workloads": {},
  "digests": {"sha256:1111111111111111111111111111111111111111111111111111111111111111": "ghcr.io/x/app:v1"},
  "schema": "c8s.allowlist/v1"
}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCmd("canonicalize", path)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := digestTestDoc[:len(digestTestDoc)-1] + `,"workloads":{}}` + "\n"
	if out != want {
		t.Fatalf("canonical output = %q, want %q", out, want)
	}
}

func TestCanonicalizeCmdRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(path, []byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{},"identity":"unsupported"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd("canonicalize", path); err == nil {
		t.Fatal("canonicalize accepted an unknown field")
	}
}
