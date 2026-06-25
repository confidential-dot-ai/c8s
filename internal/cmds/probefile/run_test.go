package probefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbePassesOnNonEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := probe(path); err != nil {
		t.Fatalf("probe(non-empty file) = %v, want nil", err)
	}
}

func TestProbeFailsOnMissingFile(t *testing.T) {
	if err := probe(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("probe(missing) = nil, want error")
	}
}

func TestProbeFailsOnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}

	err := probe(path)
	if err == nil {
		t.Fatal("probe(empty) = nil, want error")
	}
}

func TestProbeFailsOnDirectory(t *testing.T) {
	if err := probe(t.TempDir()); err == nil {
		t.Fatal("probe(dir) = nil, want error")
	}
}
