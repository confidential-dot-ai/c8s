//go:build linux

package ratlsmesh

import (
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// A connection that never went through iptables REDIRECT must be rejected.
// Without conntrack both family probes fail and the error must come from the
// final IPv4 fallback, never a synthesized zero address; with conntrack the
// kernel answers with the listener's own address, which must be refused as a
// direct dial (forwarding there would loop the proxy onto itself).
func TestDefaultOrigDstFuncFailsWithoutRedirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		acceptedCh <- c
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted := <-acceptedCh
	defer accepted.Close()

	// The proxy reads the original destination from the connection it
	// accepted, so probe that side, not the client's.
	dst, err := defaultOrigDstFunc(accepted)
	if err == nil {
		t.Fatalf("defaultOrigDstFunc succeeded with %q on a non-redirected connection", dst)
	}
	if !strings.Contains(err.Error(), "getsockopt IPv4") && !strings.Contains(err.Error(), "dialed directly") {
		t.Errorf("error = %v, want the IPv4-fallback getsockopt failure or the direct-dial rejection", err)
	}
}

func TestDefaultOrigDstFuncRejectsNonTCP(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := defaultOrigDstFunc(a)
	if err == nil || !strings.Contains(err.Error(), "not a TCP connection") {
		t.Errorf("error = %v, want not-a-TCP-connection", err)
	}
}

// Without CAP_NET_ADMIN the conntrack delete fails, which must surface as the
// flush-failed warning; the filter-build step must stay silent for valid IPs.
func TestFlushCWConntrackReachesDeleteForValidIPs(t *testing.T) {
	logsFor := func(ips []string) string {
		var buf syncBuffer
		flushCWConntrack(slog.New(slog.NewJSONHandler(&buf, nil)), ips)
		return buf.String()
	}

	out := logsFor([]string{"10.99.88.7"})
	records := decodeLogRecords(out)
	if hasMsg(records, "build cw conntrack filter failed") {
		t.Errorf("filter build warned for a valid IP: %s", out)
	}
	flushed := hasMsg(records, "flushed cw conntrack entries so the guard fails closed")
	failed := hasMsg(records, "cw conntrack flush failed")
	if !flushed && !failed {
		t.Errorf("no evidence the conntrack delete ran; logs: %s", out)
	}

	// Unparseable IPs are dropped by the family split: no netlink call, no log.
	if out := logsFor([]string{"not-an-ip"}); strings.TrimSpace(out) != "" {
		t.Errorf("unexpected logs for unparseable IP: %s", out)
	}
	if out := logsFor(nil); strings.TrimSpace(out) != "" {
		t.Errorf("unexpected logs for empty IP list: %s", out)
	}
}

// The kernel routes loopback via lo; a working RouteGet+LinkByIndex pair must
// answer (true, nil) for an lo allowlist and (false, nil) otherwise.
func TestDefaultLocalRouteCheckLoopbackStrict(t *testing.T) {
	ok, err := defaultLocalRouteCheck("127.0.0.1", []string{"lo"})
	if err != nil {
		t.Fatalf("defaultLocalRouteCheck(127.0.0.1, lo) error: %v", err)
	}
	if !ok {
		t.Error("route to 127.0.0.1 must use lo")
	}
	ok, err = defaultLocalRouteCheck("127.0.0.1", []string{"definitely-not-an-iface"})
	if err != nil {
		t.Fatalf("unexpected error for non-matching allowlist: %v", err)
	}
	if ok {
		t.Error("route to 127.0.0.1 must not match a bogus allowlist")
	}
}

func TestNtohs(t *testing.T) {
	kernel := [2]byte{0x1f, 0x90} // 8080 in network byte order
	n := binary.NativeEndian.Uint16(kernel[:])
	if got := ntohs(n); got != 8080 {
		t.Errorf("ntohs = %d, want 8080", got)
	}
}
