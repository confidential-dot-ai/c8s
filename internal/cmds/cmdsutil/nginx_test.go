package cmdsutil

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

		pid, err := findNginxMasterPID(root)
		if err != nil {
			t.Fatalf("findNginxMasterPID: %v", err)
		}
		if pid != 200 {
			t.Fatalf("pid = %d, want 200", pid)
		}
	})

	t.Run("no master present", func(t *testing.T) {
		root := t.TempDir()
		if _, err := findNginxMasterPID(root); err == nil {
			t.Fatal("findNginxMasterPID succeeded, want no-master error")
		}
	})

	t.Run("proc root unreadable", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "missing")
		if _, err := findNginxMasterPID(root); err == nil {
			t.Fatal("findNginxMasterPID succeeded, want read error")
		}
	})
}

func TestReloadNginx(t *testing.T) {
	t.Run("signals the master", func(t *testing.T) {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		t.Cleanup(func() { signal.Stop(hup) })
		root := t.TempDir()
		dir := filepath.Join(root, strconv.Itoa(os.Getpid()))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, value := range map[string]string{"comm": "nginx\n", "cmdline": "nginx: master process\x00"} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := ReloadNginx(root, slog.Default()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-hup:
		case <-time.After(5 * time.Second):
			t.Fatal("SIGHUP not delivered")
		}
	})
	t.Run("no master", func(t *testing.T) {
		if err := ReloadNginx(t.TempDir(), slog.Default()); err == nil {
			t.Fatal("ReloadNginx succeeded, want no-master error")
		}
	})
}
