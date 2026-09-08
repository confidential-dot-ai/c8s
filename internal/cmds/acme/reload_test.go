package acme

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// overrideProcRoot substitutes a fake /proc tree and restores the real one on
// cleanup.
func overrideProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// presentAsNginxMaster makes ReloadNginx find this test process under root.
func presentAsNginxMaster(t *testing.T, root string) {
	t.Helper()
	pidDir := filepath.Join(root, strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("nginx: master process\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// catchSIGHUP subscribes for the reload signal ReloadNginx sends the master.
func catchSIGHUP(t *testing.T) <-chan os.Signal {
	t.Helper()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })
	return hup
}
