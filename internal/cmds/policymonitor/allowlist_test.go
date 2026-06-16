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

func TestExtractDigest_PrioritiesAndFallthrough(t *testing.T) {
	// Note the uppercase A in the image-name to confirm normalisation
	// returns a lowercase sha256:<hex> regardless of input case.
	tests := []struct {
		name        string
		annotations map[string]string
		want        string
		wantOK      bool
	}{
		{
			name: "image-name-with-digest",
			annotations: map[string]string{
				"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/assam@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			want:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantOK: true,
		},
		{
			name: "fallback-to-image-id",
			annotations: map[string]string{
				"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/assam:v1.0.0",
				"io.kubernetes.cri.image-id":   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
			want:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			wantOK: true,
		},
		{
			name: "fallback-to-ref-name",
			annotations: map[string]string{
				"io.kubernetes.cri.image-name":      "ghcr.io/confidential-dot-ai/assam:v1.0.0",
				"org.opencontainers.image.ref.name": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
			want:   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			wantOK: true,
		},
		{
			name:        "no-annotations",
			annotations: nil,
			wantOK:      false,
		},
		{
			name: "all-malformed",
			annotations: map[string]string{
				"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/assam:v1.0.0",
				"io.kubernetes.cri.image-id":   "not-a-digest",
			},
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractDigest(tc.annotations)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tc.wantOK, got)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsSandbox(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "containerd cri sandbox",
			annotations: map[string]string{"io.kubernetes.cri.container-type": "sandbox"},
			want:        true,
		},
		{
			name:        "cri-o sandbox",
			annotations: map[string]string{"io.kubernetes.cri-o.ContainerType": "sandbox"},
			want:        true,
		},
		{
			name:        "workload container",
			annotations: map[string]string{"io.kubernetes.cri.container-type": "container"},
			want:        false,
		},
		{
			name:        "no container-type annotation",
			annotations: map[string]string{"io.kubernetes.cri.image-name": "ghcr.io/x:latest"},
			want:        false,
		},
		{
			name:        "nil annotations",
			annotations: nil,
			want:        false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSandbox(tc.annotations); got != tc.want {
				t.Errorf("isSandbox = %v, want %v", got, tc.want)
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
