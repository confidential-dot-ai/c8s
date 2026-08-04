//go:build linux

package workloadclaims

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// peerFromPidfd builds a Peer that pins pid via a real pidfd, mirroring what
// peerFrom does from SO_PEERPIDFD — so the liveness check can be exercised
// without a socket pair.
func peerFromPidfd(t *testing.T, pid int) Peer {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}
	return Peer{pid: pid, pidfd: fd}
}

// A pidfd pinning a live process reports IsAlive; once that process exits (its
// PID now reusable), IsAlive reports false so the resolver fails closed instead
// of binding the caller to whatever now holds the number.
func TestPeerIsAliveTracksProcessExit(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	peer := peerFromPidfd(t, cmd.Process.Pid)
	defer peer.Close()

	if !peer.IsAlive() {
		t.Fatal("IsAlive = false for a running process")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	_ = cmd.Wait() // reap, so the kernel signals the pidfd

	if peer.IsAlive() {
		t.Fatal("IsAlive = true after the pinned process exited (PID-reuse window left open)")
	}
}

// A Peer with no pidfd fails closed: on a supported CC kernel SO_PEERPIDFD is
// always present, so its absence must not read as "alive". The test-only
// PeerForPID is the one exception (pidfdSkip), so resolver tests still run.
func TestPeerIsAliveFailsClosedWithoutPidfd(t *testing.T) {
	if (Peer{pid: 1234, pidfd: pidfdNone}).IsAlive() {
		t.Fatal("IsAlive = true with no pidfd; a real node must fail closed")
	}
	if !PeerForPID(1234).IsAlive() {
		t.Fatal("IsAlive = false for a test peer; PeerForPID must skip the check")
	}
}
