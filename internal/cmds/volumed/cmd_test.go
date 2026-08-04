package volumed

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func goodConfig(dir string) config {
	return config{
		socketDir:   dir,
		kubeletRoot: "/var/lib/kubelet",
		cgroupRoot:  DefaultCgroupRoot,
		// InventorySocketGID needs root; our own gid still proves the chgrp.
		socketGID:    os.Getgid(),
		reapInterval: 15 * time.Second,
		maxMounts:    64,
	}
}

func TestValidateAcceptsACompleteConfig(t *testing.T) {
	if err := validate(goodConfig(t.TempDir())); err != nil {
		t.Fatalf("rejected a complete config: %v", err)
	}
}

func TestValidateRequiresEveryDependency(t *testing.T) {
	cases := map[string]func(*config){
		"socket dir":    func(c *config) { c.socketDir = "" },
		"kubelet root":  func(c *config) { c.kubeletRoot = "" },
		"cgroup root":   func(c *config) { c.cgroupRoot = "" },
		"reap interval": func(c *config) { c.reapInterval = -1 },
		"max mounts":    func(c *config) { c.maxMounts = 0 },
	}
	for name, mutate := range cases {
		cfg := goodConfig(t.TempDir())
		mutate(&cfg)
		if err := validate(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The daemon makes no network calls, so a full run is exercised here: it serves
// on its socket and unwinds when its context goes.
func TestRunDaemonServesUntilItsContextIsDone(t *testing.T) {
	cfg := goodConfig(t.TempDir())
	cfg.kubeletRoot, cfg.cgroupRoot = t.TempDir(), t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, cfg) }()

	sock := filepath.Join(cfg.socketDir, SocketName)
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the daemon never created its socket")
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runDaemon: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runDaemon did not return after its context was cancelled")
	}
}

func TestRunDaemonRejectsAnIncompleteConfig(t *testing.T) {
	if err := runDaemon(context.Background(), config{}); err == nil {
		t.Fatal("ran with nothing configured")
	}
}

func TestRunDaemonReportsAnUnusableSocketDir(t *testing.T) {
	cfg := goodConfig(filepath.Join(t.TempDir(), "absent"))
	cfg.kubeletRoot, cfg.cgroupRoot = t.TempDir(), t.TempDir()
	if err := runDaemon(context.Background(), cfg); err == nil {
		t.Fatal("ran with a socket directory that does not exist")
	}
}

func TestListenCreatesTheSocketGroupWritable(t *testing.T) {
	dir := t.TempDir()
	l, err := listen(dir, os.Getgid())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	path := filepath.Join(dir, SocketName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode is %o, want 660", perm)
	}
	// Group-owned, or the non-root fetcher sidecar cannot connect. Chgrp to our
	// own gid, since InventorySocketGID needs root.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	if int(st.Gid) != os.Getgid() {
		t.Errorf("socket gid = %d, want %d", st.Gid, os.Getgid())
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Error("not a socket")
	}
}

// A socket left by a previous run is replaced; without this the daemon could
// not restart.
func TestListenReplacesAStaleSocket(t *testing.T) {
	dir := t.TempDir()
	first, err := listen(dir, os.Getgid())
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	first.Close()

	second, err := listen(dir, os.Getgid())
	if err != nil {
		t.Fatalf("second listen over a stale socket: %v", err)
	}
	defer second.Close()

	if _, err := net.Dial("unix", filepath.Join(dir, SocketName)); err != nil {
		t.Fatalf("the replacement socket does not accept: %v", err)
	}
}

// Only this daemon's own socket name is removed: the directory is the
// inventory's, and its socket is what every confidential pod needs to start.
func TestListenLeavesTheInventorySocketAlone(t *testing.T) {
	dir := t.TempDir()
	neighbour := filepath.Join(dir, "workload-claims.sock")
	other, err := net.Listen("unix", neighbour)
	if err != nil {
		t.Fatalf("neighbour listen: %v", err)
	}
	defer other.Close()

	l, err := listen(dir, os.Getgid())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(neighbour); err != nil {
		t.Fatalf("the inventory's socket was removed: %v", err)
	}
	if _, err := net.Dial("unix", neighbour); err != nil {
		t.Fatalf("the inventory's socket no longer accepts: %v", err)
	}
}

func TestListenReportsAnUnusableDirectory(t *testing.T) {
	if _, err := listen(filepath.Join(t.TempDir(), "absent"), os.Getgid()); err == nil {
		t.Fatal("listened in a directory that does not exist")
	}
}

func TestNewCmdHasTheDaemonFlags(t *testing.T) {
	cmd := NewCmd()
	for _, flag := range []string{"socket-dir", "kubelet-root", "cgroup-root", "reap-interval", "max-mounts"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing --%s", flag)
		}
	}
}
