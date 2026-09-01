package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestCanonicalizeIsOfflineAndUsesLibraryCanonicalForm(t *testing.T) {
	input := `{
  "workloads": {"z":{"containers":[{"args":{"policy":"deny"},"command":{"argv":["/z"],"policy":"exact"},"digest":"` + digB + `"}]}},
  "digests": {"` + digA + `":"base"},
  "schema": "c8s.allowlist/v1"
}`
	path := writeFile(t, "allowlist.json", input)

	out, _, err := runCmd("canonicalize", path)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	al, err := pkgallowlist.ParseJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("canonical output differs\ngot:  %s\nwant: %s", out, want)
	}
	if strings.HasSuffix(out, "\n") {
		t.Fatal("canonicalize added a byte that is not in Canonical()")
	}
}

func TestCanonicalizeReadsStdin(t *testing.T) {
	input := `{"schema":"c8s.allowlist/v1"}`
	cmd := NewCmd()
	cmd.SetArgs([]string{"canonicalize", "-"})
	cmd.SetIn(strings.NewReader(input))
	var out strings.Builder
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("canonicalize stdin: %v", err)
	}
	if got, want := out.String(), `{"schema":"c8s.allowlist/v1","digests":null,"workloads":null}`; got != want {
		t.Fatalf("canonical stdin output = %q, want %q", got, want)
	}
}

func TestDigestHashesCanonicalBytes(t *testing.T) {
	path := writeFile(t, "allowlist.json", `{"workloads":{},"schema":"c8s.allowlist/v1","digests":{}}`)
	canonical, _, err := runCmd("canonicalize", path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canonical))
	want := "sha256:" + hex.EncodeToString(sum[:]) + "\n"
	out, _, err := runCmd("digest", path)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if out != want {
		t.Fatalf("digest output = %q, want %q", out, want)
	}
}

func TestCanonicalCommandsRejectInvalidDocuments(t *testing.T) {
	path := writeFile(t, "bad.json", `{"schema":"c8s.allowlist/v1","unknown":true}`)
	for _, name := range []string{"canonicalize", "digest"} {
		if _, _, err := runCmd(name, path); err == nil {
			t.Fatalf("%s accepted an invalid document", name)
		}
	}
}

func TestCanonicalCommandsDoNotRewriteInput(t *testing.T) {
	input := `{"schema":"c8s.allowlist/v1"}`
	path := writeFile(t, "allowlist.json", input)
	if _, _, err := runCmd("canonicalize", path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != input {
		t.Fatalf("input changed: %q", after)
	}
}
