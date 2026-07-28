package workloadclaims

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// pidfd sentinels for Peer.pidfd. A real pidfd is >= 0.
const (
	// pidfdNone: peerFrom obtained no pidfd (non-unix conn, or SO_PEERPIDFD
	// failed). A CC node always supports SO_PEERPIDFD — it landed in Linux 6.5,
	// and SNP hosts require >= 6.11, TDX >= 6.16 — so its absence is anomalous,
	// not an old-kernel we tolerate. IsAlive fails closed on it.
	pidfdNone = -1
	// pidfdSkip: a test-constructed Peer (PeerForPID) with no socket, so there
	// is no liveness to check. IsAlive returns true so resolver tests can run
	// without a real process. Never produced by peerFrom.
	pidfdSkip = -2
)

// Peer identifies the process on the other end of an inventory connection. The
// PID comes from SO_PEERCRED; SO_PEERPIDFD (Linux 6.5+) additionally returns a
// pidfd that pins that exact process instance, so IsAlive can detect an exit
// between the credential read and the resolver's /proc lookup — the window a
// bare PID leaves open to PID reuse (docs/getcert-workload-binding.md,
// "Corner 1"). Close releases the pidfd.
type Peer struct {
	pid   int
	pidfd int // >= 0: a live pidfd to poll; pidfdNone/pidfdSkip otherwise
}

// peerFrom captures the peer credentials of a unix connection. A non-unix conn
// or a failed SO_PEERCRED yields a zero-PID Peer, which the node-CVM resolver
// rejects. SO_PEERPIDFD must succeed on a CC node; any failure leaves pidfdNone,
// and IsAlive then fails closed rather than vouching for a caller it cannot pin.
func peerFrom(c net.Conn) Peer {
	p := Peer{pidfd: pidfdNone}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return p
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return p
	}
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil || cred == nil {
			return
		}
		p.pid = int(cred.Pid)
		// SO_PEERPIDFD reflects the peer captured at connect(), consistent with
		// SO_PEERCRED above, so the pidfd pins the same process the PID names.
		// Any failure (including ENOPROTOOPT on a sub-6.5 kernel we do not
		// support) leaves pidfdNone → fail closed.
		if pidfd, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD); err == nil {
			p.pidfd = pidfd
		}
	})
	return p
}

// PID returns the peer's kernel-reported PID, or 0 when unavailable.
func (p Peer) PID() int { return p.pid }

// IsAlive reports whether the pinned peer process is confirmed still running.
// It MUST be called AFTER the resolver reads /proc for this PID: a peer that
// exited during resolution may have had its PID recycled, so the read cannot be
// trusted. It fails closed (returns false) when it cannot confirm liveness — no
// pidfd, a bad pidfd, or a poll error — so only a positively-confirmed live
// process passes.
func (p Peer) IsAlive() bool {
	if p.pidfd == pidfdSkip {
		return true // test peer: no socket, nothing to verify
	}
	if p.pidfd < 0 {
		return false // no pidfd on a node that must have one → fail closed
	}
	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	// Poll with timeout 0 is non-blocking; bound the (rare) EINTR retry rather
	// than spin, and fail closed if it never settles.
	for i := 0; i < 8; i++ {
		_, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false
		}
		// A bad, errored, or hung-up fd must not read as "alive".
		if fds[0].Revents&(unix.POLLNVAL|unix.POLLERR|unix.POLLHUP) != 0 {
			return false
		}
		// A pidfd becomes readable (POLLIN) exactly when its process exits.
		return fds[0].Revents&unix.POLLIN == 0
	}
	return false
}

// Close releases the pidfd, if any. Safe to call on a zero or test Peer.
func (p Peer) Close() {
	if p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
	}
}

// PeerForPID builds a Peer from a PID obtained out of band, with no pidfd — its
// liveness check is skipped (pidfdSkip). Production inventory code always uses
// peerFrom, which pins a pidfd; this exists only for tests exercising the
// resolver without a real socket.
func PeerForPID(pid int) Peer { return Peer{pid: pid, pidfd: pidfdSkip} }
