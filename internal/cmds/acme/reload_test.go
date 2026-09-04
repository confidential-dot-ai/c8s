package acme

import (
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// overrideProcRoot substitutes a fake /proc tree and restores the real one on
// cleanup.
func overrideProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// presentAsNginxMaster makes reloadNginx find this test process under root.
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

// catchSIGHUP subscribes for the reload signal reloadNginx sends the master.
func catchSIGHUP(t *testing.T) <-chan os.Signal {
	t.Helper()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })
	return hup
}

func TestFindNginxMasterPID(t *testing.T) {
	t.Run("finds the master among decoys", func(t *testing.T) {
		root := t.TempDir()
		writeProcEntry := func(pid, comm, cmdline string) {
			t.Helper()
			dir := filepath.Join(root, pid)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if comm != "" {
				if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if cmdline != "" {
				if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		// Decoys exercising every skip branch: a non-pid dir, a plain file, a
		// non-nginx process, an nginx worker, an nginx without cmdline.
		writeProcEntry("self", "nginx\n", "nginx: master process\x00")
		if err := os.WriteFile(filepath.Join(root, "42"), []byte("file"), 0o644); err != nil {
			t.Fatal(err)
		}
		writeProcEntry("100", "bash\n", "bash\x00")
		writeProcEntry("101", "nginx\n", "nginx: worker process\x00")
		writeProcEntry("102", "nginx\n", "")
		writeProcEntry("103", "", "nginx: master process\x00")
		writeProcEntry("200", "nginx\n", "nginx: master process /etc/nginx/nginx.conf\x00")
		overrideProcRoot(t, root)

		pid, err := findNginxMasterPID()
		if err != nil {
			t.Fatalf("findNginxMasterPID: %v", err)
		}
		if pid != 200 {
			t.Fatalf("pid = %d, want 200", pid)
		}
	})

	t.Run("no master present", func(t *testing.T) {
		overrideProcRoot(t, t.TempDir())
		if _, err := findNginxMasterPID(); err == nil {
			t.Fatal("findNginxMasterPID succeeded, want no-master error")
		}
	})

	t.Run("proc root unreadable", func(t *testing.T) {
		overrideProcRoot(t, filepath.Join(t.TempDir(), "missing"))
		if _, err := findNginxMasterPID(); err == nil {
			t.Fatal("findNginxMasterPID succeeded, want read error")
		}
	})
}

func TestReloadNginx(t *testing.T) {
	t.Run("signals the master", func(t *testing.T) {
		hup := catchSIGHUP(t)
		root := t.TempDir()
		presentAsNginxMaster(t, root)
		overrideProcRoot(t, root)

		if err := reloadNginx(slog.Default()); err != nil {
			t.Fatalf("reloadNginx: %v", err)
		}
		select {
		case <-hup:
		case <-time.After(5 * time.Second):
			t.Fatal("SIGHUP not delivered")
		}
	})

	t.Run("no master", func(t *testing.T) {
		overrideProcRoot(t, t.TempDir())
		if err := reloadNginx(slog.Default()); err == nil {
			t.Fatal("reloadNginx succeeded, want no-master error")
		}
	})
}
