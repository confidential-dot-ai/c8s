package cmdsutil

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ReloadNginx finds the nginx master in procRoot and sends SIGHUP.
// The caller must share its process namespace with nginx.
func ReloadNginx(procRoot string, log *slog.Logger) error {
	pid, err := findNginxMasterPID(procRoot)
	if err != nil {
		return err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("SIGHUP nginx (pid %d): %w", pid, err)
	}
	log.Info("sent SIGHUP to nginx", "pid", pid)
	return nil
}

// findNginxMasterPID scans /proc for the nginx master process.
// Match: /proc/<pid>/comm == "nginx" AND cmdline contains "master".
func findNginxMasterPID(procRoot string) (int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", procRoot, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(procRoot + "/" + e.Name() + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "nginx" {
			continue
		}
		cmdline, err := os.ReadFile(procRoot + "/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline is NUL-separated; nginx master argv[0] is
		// "nginx: master process ...".
		if !strings.Contains(string(cmdline), "master") {
			continue
		}
		return pid, nil
	}
	return 0, fmt.Errorf("no nginx master process found")
}
