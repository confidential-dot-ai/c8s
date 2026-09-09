//go:build linux

package policymonitor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadAllowlist_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "ok.json", `{
		"_comment": "ignored",
		"sha256_digests": [
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		]
	}`)
	a, warnings, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if a.Size() != 2 {
		t.Fatalf("Size = %d, want 2", a.Size())
	}
	if !a.Contains("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("missing first digest")
	}
	// Case-insensitive match: input upper-case, allowlist normalises to lower.
	if !a.Contains("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("missing second digest (case-insensitive)")
	}
}

func TestLoadAllowlist_MalformedEntriesAreWarnedNotFatal(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "mixed.json", `{
		"sha256_digests": [
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"not-a-digest",
			""
		]
	}`)
	a, warnings, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if a.Size() != 1 {
		t.Fatalf("Size = %d, want 1", a.Size())
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %d, want 2", len(warnings))
	}
}

func TestLoadAllowlist_EmptyIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "empty.json", `{"sha256_digests": []}`)
	_, _, err := loadAllowlist(path)
	if err == nil {
		t.Fatal("expected error for empty allowlist")
	}
	if !strings.Contains(err.Error(), "no valid digests") {
		t.Errorf("error message %q does not mention empty allowlist", err.Error())
	}
}

func TestLoadAllowlist_MissingFile(t *testing.T) {
	_, _, err := loadAllowlist("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v does not wrap ErrNotExist", err)
	}
}

// The accepted input forms are pinned by pkg/types; this only asserts the
// package's map-key contract — bare hex out, errors passed through.
func TestNormalizeDigestReturnsBareHex(t *testing.T) {
	hex := strings.Repeat("a", 64)
	if got, err := normalizeDigest("sha256:" + hex); err != nil || got != hex {
		t.Fatalf("normalizeDigest = %q, %v; want the bare hex", got, err)
	}
	if _, err := normalizeDigest("ghcr.io/confidential-dot-ai/assam:v1.0.0"); err == nil {
		t.Fatal("a tag-only reference was accepted")
	}
}

func TestAllowlistNilReceivers(t *testing.T) {
	var a *allowlist
	if a.Contains("sha256:" + strings.Repeat("a", 64)) {
		t.Error("nil allowlist Contains should be false")
	}
	if a.Size() != 0 {
		t.Error("nil allowlist Size should be 0")
	}
}

func TestAllowlistContains_Malformed(t *testing.T) {
	a := newSeededAllowlist(t, "sha256:"+strings.Repeat("a", 64))
	if a.Contains("garbage") {
		t.Error("Contains should be false for malformed input")
	}
	if a.Contains("") {
		t.Error("Contains should be false for empty input")
	}
}

func TestLoadAllowlist_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAllowlist(path); err == nil {
		t.Fatal("expected parse error for malformed allowlist JSON")
	}
}
