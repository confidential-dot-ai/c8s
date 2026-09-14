//go:build linux

package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestDetectMountStorage(t *testing.T) {
	if got := detectMountStorage(t.TempDir()); got != allowlist.MountUnknown {
		t.Fatalf("ordinary filesystem = %q, want unknown", got)
	}
	if got := detectMountStorage("/dev/shm"); got != allowlist.MountMemory {
		t.Fatalf("tmpfs = %q, want memory", got)
	}
}

func TestC8sCryptDeviceThroughVerity(t *testing.T) {
	root := t.TempDir()
	crypt := filepath.Join(root, "crypt")
	verity := filepath.Join(root, "verity")
	if err := os.MkdirAll(filepath.Join(crypt, "dm"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(verity, "slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crypt, "dm/name"), []byte("c8s-crypt-pod-data\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crypt, "dm/uuid"), []byte("CRYPT-PLAIN-test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(crypt, filepath.Join(verity, "slaves", "crypt")); err != nil {
		t.Fatal(err)
	}
	if !hasC8sCryptDevice(verity, map[string]bool{}) {
		t.Fatal("verity above c8s dm-crypt was not recognised")
	}
	if err := os.WriteFile(filepath.Join(crypt, "dm/uuid"), []byte("DM-LINEAR-test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if hasC8sCryptDevice(verity, map[string]bool{}) {
		t.Fatal("a device name without a crypt target was trusted")
	}
	if hasC8sCryptDevice(filepath.Join(root, "missing"), map[string]bool{}) {
		t.Fatal("unknown device reported encrypted")
	}
}
