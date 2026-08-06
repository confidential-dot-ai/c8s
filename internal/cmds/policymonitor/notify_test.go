//go:build linux

package policymonitor

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listenNotify binds a unixgram socket and returns its address plus a channel
// carrying the first datagram, standing in for systemd's notify socket.
func listenNotify(t *testing.T, addr string) <-chan string {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen %q: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		got <- string(buf[:n])
	}()
	return got
}

func awaitNotify(t *testing.T, got <-chan string) string {
	t.Helper()
	select {
	case msg := <-got:
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("no datagram on the notify socket")
		return ""
	}
}

func TestNotifyReady_PathSocket(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "notify")
	got := listenNotify(t, addr)
	if err := notifyReadyTo(addr); err != nil {
		t.Fatalf("notifyReadyTo: %v", err)
	}
	if msg := awaitNotify(t, got); msg != "READY=1" {
		t.Errorf("got %q, want READY=1", msg)
	}
}

// systemd hands out an abstract socket ("@/org/freedesktop/systemd1/notify")
// under some configurations; the leading '@' is a NUL in sun_path.
func TestNotifyReady_AbstractSocket(t *testing.T) {
	got := listenNotify(t, "\x00c8s-policy-monitor-notify-test")
	if err := notifyReadyTo("@c8s-policy-monitor-notify-test"); err != nil {
		t.Fatalf("notifyReadyTo: %v", err)
	}
	if msg := awaitNotify(t, got); msg != "READY=1" {
		t.Errorf("got %q, want READY=1", msg)
	}
}

// Outside the unit there is no socket to write to and readiness is a no-op.
func TestNotifyReady_NoSocketIsNoOp(t *testing.T) {
	if err := notifyReadyTo(""); err != nil {
		t.Errorf("notifyReadyTo(\"\") = %v, want nil", err)
	}
}

func TestNotifyReady_UnreachableSocketErrors(t *testing.T) {
	if err := notifyReadyTo(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("notifyReadyTo on an unbound socket returned nil, want an error")
	}
}

// READY=1 is sent on the first watch generation only; kata-agent's start job is
// released once and later generations must not re-announce.
func TestSignalReady_OncePerProcess(t *testing.T) {
	m, _, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	calls := 0
	m.ready = func() error { calls++; return nil }

	m.signalReady()
	m.signalReady()
	m.signalReady()

	if calls != 1 {
		t.Errorf("ready called %d times, want 1", calls)
	}
}

// A monitor built outside runMonitor (tests, and the code path before the
// notify hook is wired) must not panic on a nil hook.
func TestSignalReady_NilHook(t *testing.T) {
	m, _, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.ready = nil
	m.signalReady()
}
