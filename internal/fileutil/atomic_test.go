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

	if err := WriteAtomic(path, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q, want new", got)
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
