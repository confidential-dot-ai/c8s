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

func TestNormalizeDigest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"prefixed", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"bare", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"image-ref-with-digest", "ghcr.io/confidential-dot-ai/assam@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"uppercase-normalised", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"empty", "", "", true},
		{"too-short", "sha256:abc", "", true},
		{"non-hex", "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "", true},
		{"tag-only", "ghcr.io/confidential-dot-ai/assam:v1.0.0", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeDigest(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeDigest(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeDigest(%q) err = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeDigest(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAllowlistMergePulled(t *testing.T) {
	dir := t.TempDir()
	seed := "sha256:" + strings.Repeat("a", 64)
	path := writeFile(t, dir, "seed.json", `{"sha256_digests":["`+seed+`"]}`)
	a, _, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if a.Size() != 1 {
		t.Fatalf("seed size = %d, want 1", a.Size())
	}

	pulled := "sha256:" + strings.Repeat("b", 64)
	// One new, one duplicate-of-seed, one malformed → only the new counts.
	if added := a.MergePulled([]string{pulled, seed, "not-a-digest"}); added != 1 {
		t.Fatalf("MergePulled added = %d, want 1", added)
	}
	if a.Size() != 2 {
		t.Fatalf("size after merge = %d, want 2", a.Size())
	}
	if !a.Contains(pulled) {
		t.Errorf("Contains(pulled) = false, want true")
	}
	if !a.Contains(seed) {
		t.Errorf("Contains(seed) = false, want true (merge must never drop the seed)")
	}
	// Re-merging the same set adds nothing.
	if again := a.MergePulled([]string{pulled, seed}); again != 0 {
		t.Errorf("re-merge added = %d, want 0", again)
	}
}

// TestAllowlistMergeConcurrent is a race-detector smoke test: concurrent
// Contains/Size reads while MergePulled writes. Earns its keep under
// `go test -race`.
func TestAllowlistMergeConcurrent(t *testing.T) {
	dir := t.TempDir()
	seed := "sha256:" + strings.Repeat("a", 64)
	path := writeFile(t, dir, "seed.json", `{"sha256_digests":["`+seed+`"]}`)
	a, _, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			a.Contains(seed)
			a.Size()
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		a.MergePulled([]string{"sha256:" + strings.Repeat("c", 64)})
	}
	<-done
}

func TestAllowlistNilReceivers(t *testing.T) {
	var a *allowlist
	if a.Contains("sha256:" + strings.Repeat("a", 64)) {
		t.Error("nil allowlist Contains should be false")
	}
	if a.Size() != 0 {
		t.Error("nil allowlist Size should be 0")
	}
	if a.MergePulled([]string{"sha256:" + strings.Repeat("a", 64)}) != 0 {
		t.Error("nil allowlist MergePulled should add 0")
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
