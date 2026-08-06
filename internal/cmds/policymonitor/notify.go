//go:build linux

package policymonitor

// sd_notify(3) readiness, hand-rolled against $NOTIFY_SOCKET.
//
// policy-monitor.service is Type=notify and kata-agent.service Requires= it, so
// READY=1 is what releases kata-agent's start job. It is sent once the inotify
// watch is installed and the first seed pass has dispatched — the point from
// which every bundle kata-agent creates gets a decision.

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// notifySocketEnv is systemd's rendezvous with a Type=notify service.
const notifySocketEnv = "NOTIFY_SOCKET"

// notifyReady sends READY=1 to systemd. Absent $NOTIFY_SOCKET it does nothing,
// which is the debug-shell and test case.
func notifyReady() error {
	return notifyReadyTo(os.Getenv(notifySocketEnv))
}

func notifyReadyTo(addr string) error {
	if addr == "" {
		return nil
	}
	// A leading '@' names an abstract socket, whose sun_path starts with NUL.
	if strings.HasPrefix(addr, "@") {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("dial %s %q: %w", notifySocketEnv, addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		return fmt.Errorf("write READY=1: %w", err)
	}
	return nil
}
