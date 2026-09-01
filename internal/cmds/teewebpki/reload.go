package teewebpki

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// procRoot is a variable only so tests can replace procfs.
var procRoot = "/proc"

// reloadNginx sends SIGHUP to the nginx master in the shared process
// namespace. The helper does not run a shell or trust a PID file.
func reloadNginx() error {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return fmt.Errorf("read %s: %w", procRoot, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		base := procRoot + "/" + entry.Name()
		comm, err := os.ReadFile(base + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "nginx" {
			continue
		}
		cmdline, err := os.ReadFile(base + "/cmdline")
		if err != nil || !strings.Contains(string(cmdline), "master") {
			continue
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find nginx process %d: %w", pid, err)
		}
		if err := process.Signal(syscall.SIGHUP); err != nil {
			return fmt.Errorf("SIGHUP nginx process %d: %w", pid, err)
		}
		return nil
	}
	return fmt.Errorf("no nginx master process found")
}
