package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomicCreatesFileWithContentAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	data := []byte("hello world")

	if err := WriteAtomic(path, data, 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteAtomicOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 0o640 rather than 0o600: os.CreateTemp's default is 0600, so only a
	// non-default mode proves the Chmod runs and the rename replaced the
	// wider-mode original — the tightening contract secret writers rely on.
	if err := WriteAtomic(path, []byte("new"), 0o640); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Errorf("mode after overwrite = %o, want 640", info.Mode().Perm())
	}
}

func TestWriteAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := WriteAtomic(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(entries), entries)
	}
	if entries[0].Name() != "out.txt" {
		t.Errorf("leftover temp file: %s", entries[0].Name())
	}
}

func TestWriteAtomicFailsOnNonexistentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "out.txt")
	if err := WriteAtomic(path, []byte("x"), 0o644); err == nil {
		t.Fatal("expected error writing into a nonexistent directory")
	}
}

func TestWriteAtomicRenameFailureCleansUpTemp(t *testing.T) {
	dir := t.TempDir()
	// Make the destination a non-empty directory so os.Rename of a file
	// onto it fails, exercising the rename error path and tmp cleanup.
	path := filepath.Join(dir, "dest")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o755); err != nil {
		t.Fatalf("setup dir: %v", err)
	}

	if err := WriteAtomic(path, []byte("x"), 0o644); err == nil {
		t.Fatal("expected rename error when destination is a non-empty directory")
	}

	// Only the destination directory should remain; the temp file is removed.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "dest" {
		t.Errorf("temp file not cleaned up, dir contains: %v", entries)
	}
}

func TestWriteAtomicRejectsTrailingSeparator(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := WriteAtomic(dest+string(os.PathSeparator), []byte("secret"), 0o600); err == nil {
		t.Fatal("expected trailing path separator to be rejected")
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("trailing separator created nested output: %v", entries)
	}
}

func TestWriteAtomicRootStaysInOpenedDirectoryAfterPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires unprivileged symbolic links")
	}
	base := t.TempDir()
	out := filepath.Join(base, "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(out)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	moved := filepath.Join(base, "moved")
	if err := os.Rename(out, moved); err != nil {
		t.Fatalf("move opened directory: %v", err)
	}
	trap := filepath.Join(base, "trap")
	if err := os.Mkdir(trap, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(trap, out); err != nil {
		t.Fatalf("replace opened directory: %v", err)
	}

	if err := WriteAtomicRoot(root, "secret", []byte("value"), 0o600); err != nil {
		t.Fatalf("WriteAtomicRoot: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(moved, "secret"))
	if err != nil {
		t.Fatalf("read from original directory: %v", err)
	}
	if string(got) != "value" {
		t.Fatalf("original directory content = %q, want value", got)
	}
	if _, err := os.Stat(filepath.Join(trap, "secret")); !os.IsNotExist(err) {
		t.Fatalf("write followed replacement directory, stat error = %v", err)
	}
}
