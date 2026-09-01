package fileutil

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Pins the sign of the check without using RequireRAMBacked as its own
// oracle: /proc is procfs on every Linux, so an inverted check fails here
// deterministically.
func TestRequireRAMBackedRejectsProcfs(t *testing.T) {
	if err := RequireRAMBacked("/proc"); err == nil {
		t.Fatal("procfs accepted as RAM-backed")
	}
}

// Accept path against a real tmpfs mount, as volumed's tests do; skipped
// without mount privileges.
func TestRequireRAMBackedAcceptsTmpfs(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount tmpfs here (needs CAP_SYS_ADMIN in a mount namespace): %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	if err := RequireRAMBacked(dir); err != nil {
		t.Fatalf("tmpfs refused: %v", err)
	}
}
