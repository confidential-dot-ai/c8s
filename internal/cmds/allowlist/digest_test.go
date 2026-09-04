package allowlist

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const digestTestDoc = `{"schema":"c8s.allowlist/v1","digests":{"sha256:1111111111111111111111111111111111111111111111111111111111111111":"ghcr.io/x/app:v1"}}`

func writeDigestTestDoc(t *testing.T) (path, wantHex string) {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(digestTestDoc))
	if err != nil {
		t.Fatal(err)
	}
	want, err := al.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(path, []byte(digestTestDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, hex.EncodeToString(want)
}

func TestDigestCmd(t *testing.T) {
	path, want := writeDigestTestDoc(t)

	out, _, err := runCmd("digest", path)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if got := strings.TrimSpace(out); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}

	out, _, err = runCmd("digest", path, "-o", "json")
	if err != nil {
		t.Fatalf("digest -o json: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decode json output: %v", err)
	}
	if decoded["allowlist_digest"] != want {
		t.Fatalf("allowlist_digest = %s, want %s", decoded["allowlist_digest"], want)
	}
}

func TestDigestCmd_Errors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd("digest", bad); err == nil {
		t.Fatal("digest accepted an unparseable document")
	}
	if _, _, err := runCmd("digest", filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("digest accepted a missing file")
	}
}
