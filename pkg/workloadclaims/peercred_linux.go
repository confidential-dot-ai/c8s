package workloadclaims

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerPID returns the kernel-reported PID of the process on the other end of
// a unix socket, or 0 when unavailable (non-unix transport, or a failed
// getsockopt). The node-CVM resolver must reject 0 — it binds the caller to a
// pod; the kata resolver ignores the PID entirely, one pod per guest
// (docs/ratls.md).
func peerPID(c net.Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return 0
	}
	return int(cred.Pid)
}
