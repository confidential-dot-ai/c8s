//go:build linux

package ratlsmesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// syncBuffer is a goroutine-safe writer for capturing slog JSON output from
// handlers that run on their own goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logRecord is the typed shape of one slog JSON line emitted by the package.
// Addr stays raw because different records use different value types for it.
type logRecord struct {
	Level  string          `json:"level"`
	Msg    string          `json:"msg"`
	Result string          `json:"result"`
	Dir    string          `json:"dir"`
	Count  int             `json:"count"`
	TLS    *bool           `json:"tls"`
	Addr   json.RawMessage `json:"addr"`
}

// decodeLogRecords parses newline-delimited slog JSON, skipping partial
// trailing lines that may exist while the writer is still running.
func decodeLogRecords(s string) []logRecord {
	var out []logRecord
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r logRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

func recordsWithMsg(records []logRecord, msg string) []logRecord {
	var out []logRecord
	for _, r := range records {
		if r.Msg == msg {
			out = append(out, r)
		}
	}
	return out
}

func hasMsg(records []logRecord, msg string) bool {
	return len(recordsWithMsg(records, msg)) > 0
}

func TestRecordOutboundResultLabels(t *testing.T) {
	boom := fmt.Errorf("boom")
	tests := []struct {
		name       string
		fwd, rev   error
		local      bool
		wantDir    string
		wantResult string
	}{
		{"local success", nil, nil, true, "outbound_same_node", "success"},
		{"local fwd error", boom, nil, true, "outbound_same_node", "error"},
		{"local rev error", nil, boom, true, "outbound_same_node", "error"},
		{"remote success", nil, nil, false, "outbound", "success"},
		{"remote fwd error", boom, nil, false, "outbound", "error"},
		{"remote rev error", nil, boom, false, "outbound", "error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := testMetrics()
			p := &Proxy{metrics: m}
			p.recordOutbound(pipeResult{Err: tc.fwd}, pipeResult{Err: tc.rev}, tc.local)
			if got := testutil.ToFloat64(m.connectionsTotal.WithLabelValues(tc.wantDir, tc.wantResult)); got != 1 {
				t.Errorf("connectionsTotal{%s,%s} = %v, want 1", tc.wantDir, tc.wantResult, got)
			}
			// The other result bucket for the same direction must stay at 0.
			other := "success"
			if tc.wantResult == "success" {
				other = "error"
			}
			if got := testutil.ToFloat64(m.connectionsTotal.WithLabelValues(tc.wantDir, other)); got != 0 {
				t.Errorf("connectionsTotal{%s,%s} = %v, want 0", tc.wantDir, other, got)
			}
		})
	}
}

// releaseSrc must keep the per-source counter entry alive while connections
// are still in flight, and remove it only when the count reaches zero.
func TestReleaseSrcKeepsBudgetWhileHeld(t *testing.T) {
	p := &Proxy{maxConnsPerSrc: 2}
	c1, ok := p.tryAcquireSrc("10.0.0.9")
	if !ok {
		t.Fatal("first acquire failed")
	}
	if _, ok := p.tryAcquireSrc("10.0.0.9"); !ok {
		t.Fatal("second acquire failed")
	}

	// One release with one connection still held: entry must survive so the
	// budget keeps counting the in-flight connection.
	p.releaseSrc("10.0.0.9", c1)
	if got := p.srcConns["10.0.0.9"]; got != c1 {
		t.Fatal("per-source counter entry removed while a connection is still held")
	}
	if _, ok := p.tryAcquireSrc("10.0.0.9"); !ok {
		t.Fatal("third acquire should succeed after one release")
	}
	if _, ok := p.tryAcquireSrc("10.0.0.9"); ok {
		t.Fatal("fourth acquire must hit the limit: the held connection still counts")
	}

	// Full release empties the map.
	p.releaseSrc("10.0.0.9", c1)
	p.releaseSrc("10.0.0.9", c1)
	if len(p.srcConns) != 0 {
		t.Errorf("srcConns not cleaned up after full release: %v", p.srcConns)
	}
}

// A destination header of exactly max-dest-header-size bytes (newline
// included) is within the limit and must be accepted.
func TestInboundHeaderAtSizeLimitAccepted(t *testing.T) {
	backend := startBackend(t, "edge")
	serverTLS, _ := testTLSConfigs(t)

	header := backend + "\n"
	p := &Proxy{
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		maxDestHeaderSize: len(header),
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, header)
	fmt.Fprint(conn, "edge-ping")
	conn.CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from edge (got "edge-ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if v := testutil.ToFloat64(p.metrics.destHeaderErrors.WithLabelValues("read")); v != 0 {
		t.Errorf("destHeaderErrors{read} = %v for an at-limit header, want 0", v)
	}
}

// A failed RA-TLS dial happens before any handshake completes, so the access
// log must classify it as tls_error and the handshake histogram must not
// record a bogus zero-duration sample.
func TestOutboundDialFailureClassifiedAsTLSError(t *testing.T) {
	deadPort := freePort(t)
	m := testMetrics()
	var logBuf syncBuffer
	p := &Proxy{
		nodeIP:      "1.1.1.1",
		inboundPort: deadPort,
		clientTLS:   &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true},
		resolver:    &fixedRemoteResolver{nodeIP: "127.0.0.1"},
		origDstFunc: func(net.Conn) (string, error) { return "10.244.1.5:8080", nil },
		accessLog:   true,
		logger:      slog.New(slog.NewJSONHandler(&logBuf, nil)),
		metrics:     m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	assertEventually(t, 5*time.Second, func() bool {
		return len(recordsWithMsg(decodeLogRecords(logBuf.String()), "access")) > 0
	}, "access log entry never emitted for failed dial")

	access := recordsWithMsg(decodeLogRecords(logBuf.String()), "access")
	if access[0].Result != "tls_error" {
		t.Errorf("access result = %q, want tls_error (dial failed before handshake)", access[0].Result)
	}
	if n := histogramSampleCount(m.tlsHandshakeDuration.WithLabelValues("outbound", "self-signed")); n != 0 {
		t.Errorf("tlsHandshakeDuration samples = %d after failed dial, want 0", n)
	}
}

// proxyRunFixture starts a full Proxy.Run with both listeners, wired so
// outbound traffic loops through the RA-TLS inbound path to a local backend.
type proxyRunFixture struct {
	p       *Proxy
	backend string
	logBuf  *syncBuffer
	cancel  context.CancelFunc
	done    chan error
	outPort int
	inPort  int
}

func startProxyRun(t *testing.T, mutate func(*Proxy)) *proxyRunFixture {
	t.Helper()
	backend := startBackend(t, "run-e2e")
	serverTLS, clientTLS := testTLSConfigs(t)
	outPort := freePort(t)
	inPort := freePort(t)
	logBuf := &syncBuffer{}
	ready := make(chan struct{})

	p := &Proxy{
		outboundAddr: fmt.Sprintf("127.0.0.1:%d", outPort),
		inboundAddr:  fmt.Sprintf("127.0.0.1:%d", inPort),
		serverTLS:    serverTLS,
		clientTLS:    clientTLS,
		nodeIP:       "127.0.0.1",
		inboundPort:  inPort,
		resolver:     &staticResolver{nodeIP: "127.0.0.1"},
		origDstFunc:  func(net.Conn) (string, error) { return backend, nil },
		accessLog:    true,
		logger:       slog.New(slog.NewJSONHandler(logBuf, nil)),
		metrics:      testMetrics(),
		bufPool:      newBufPool(0),
		drainTimeout: time.Second,
		onReady:      func() { close(ready) },
	}
	if mutate != nil {
		mutate(p)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("proxy never became ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("proxy Run did not stop")
		}
	})
	return &proxyRunFixture{p: p, backend: backend, logBuf: logBuf, cancel: cancel, done: done, outPort: outPort, inPort: inPort}
}

func (f *proxyRunFixture) roundTrip(t *testing.T, payload string) string {
	t.Helper()
	conn, err := net.Dial("tcp", f.p.outboundAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, payload)
	conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

// End-to-end through Run: plain outbound listener, TLS inbound listener, and
// the global semaphore released after every finished connection.
func TestProxyRunEndToEnd(t *testing.T) {
	// Each app connection consumes two semaphore slots (outbound + inbound
	// leg), so capacity 2 admits exactly one connection at a time.
	f := startProxyRun(t, func(p *Proxy) {
		p.connSem = make(chan struct{}, 2)
	})

	for i := range 3 {
		want := fmt.Sprintf(`hello from run-e2e (got "ping-%d")`, i)
		if got := f.roundTrip(t, fmt.Sprintf("ping-%d", i)); got != want {
			t.Fatalf("connection %d: got %q, want %q", i, got, want)
		}
	}
	if v := testutil.ToFloat64(f.p.metrics.connLimitRejected); v != 0 {
		t.Errorf("connLimitRejected = %v after sequential connections, want 0 (slots must be released)", v)
	}

	// Listener-ready logs must report the TLS posture per listener.
	records := recordsWithMsg(decodeLogRecords(f.logBuf.String()), "listener ready")
	if len(records) != 2 {
		t.Fatalf("got %d listener-ready records, want 2", len(records))
	}
	for _, r := range records {
		var addr struct {
			Port int `json:"Port"`
		}
		if err := json.Unmarshal(r.Addr, &addr); err != nil {
			t.Fatalf("decode listener addr %s: %v", r.Addr, err)
		}
		if r.TLS == nil {
			t.Fatal("listener-ready record missing tls attribute")
		}
		switch addr.Port {
		case f.outPort:
			if *r.TLS {
				t.Error("outbound listener logged tls=true, want false")
			}
		case f.inPort:
			if !*r.TLS {
				t.Error("inbound listener logged tls=false, want true")
			}
		default:
			t.Errorf("unexpected listener port %d", addr.Port)
		}
	}
}

// A per-source rejection must return the already-acquired global semaphore
// slot; otherwise repeated per-source rejects exhaust the global limit.
func TestProxyRunPerSourceRejectReleasesGlobalSlot(t *testing.T) {
	hold := make(chan struct{})
	var holdOnce sync.Once
	release := func() { holdOnce.Do(func() { close(hold) }) }
	defer release()

	f := startProxyRun(t, func(p *Proxy) {
		p.connSem = make(chan struct{}, 2)
		p.maxConnsPerSrc = 1
		p.origDstFunc = func(net.Conn) (string, error) {
			<-hold
			return "", fmt.Errorf("held connection released")
		}
	})
	m := f.p.metrics

	conn1, err := net.Dial("tcp", f.p.outboundAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	assertEventually(t, 5*time.Second, func() bool {
		return testutil.ToFloat64(m.activeConnections.WithLabelValues("outbound")) >= 1
	}, "first connection never reached the handler")

	// Two more connections from the same source: each must be rejected on the
	// per-source budget, never on the global limit.
	for i := range 2 {
		conn, err := net.Dial("tcp", f.p.outboundAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		want := float64(i + 1)
		assertEventually(t, 5*time.Second, func() bool {
			return testutil.ToFloat64(m.connLimitPerSourceRejected) >= want
		}, "per-source rejection never counted")
	}

	if v := testutil.ToFloat64(m.connLimitRejected); v != 0 {
		t.Errorf("connLimitRejected = %v, want 0 (per-source rejects must return the global slot)", v)
	}
	release()
}

func TestTryAcquireAndReleaseSrc(t *testing.T) {
	p := &Proxy{maxConnsPerSrc: 2}
	c1, ok := p.tryAcquireSrc("10.0.0.1")
	if !ok || c1 == nil {
		t.Fatal("first acquire should succeed")
	}
	c2, ok := p.tryAcquireSrc("10.0.0.1")
	if !ok || c2 != c1 {
		t.Fatal("second acquire should succeed on the same counter")
	}
	if _, ok := p.tryAcquireSrc("10.0.0.1"); ok {
		t.Fatal("third acquire should hit the limit")
	}
	p.releaseSrc("10.0.0.1", c1)
	p.releaseSrc("10.0.0.1", c1)
	if len(p.srcConns) != 0 {
		t.Errorf("srcConns not cleaned up: %v", p.srcConns)
	}
	// A stale counter must not delete a newer one.
	fresh, _ := p.tryAcquireSrc("10.0.0.1")
	p.releaseSrc("10.0.0.1", c1) // stale: drops to -1, map entry is fresh's
	if got := p.srcConns["10.0.0.1"]; got != fresh {
		t.Error("stale release removed the fresh counter")
	}
	p.releaseSrc("10.0.0.1", fresh)
}

// TestServeConnectionLimits drives Proxy.Run so serve's semaphore and
// per-source budget branches execute in the real accept loop.
func TestServeConnectionLimits(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, tc := range []struct {
		name    string
		sem     int
		perSrc  int
		counter func(m *metrics) float64
	}{
		{"global limit", 1, 0, func(m *metrics) float64 { return testutil.ToFloat64(m.connLimitRejected) }},
		{"per-source limit", 2, 1, func(m *metrics) float64 { return testutil.ToFloat64(m.connLimitPerSourceRejected) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testMetrics()
			hold := make(chan struct{})
			var holdOnce sync.Once
			releaseHold := func() { holdOnce.Do(func() { close(hold) }) }
			defer releaseHold()

			outPort := freePort(t)
			inPort := freePort(t)
			var sem chan struct{}
			if tc.sem > 0 {
				sem = make(chan struct{}, tc.sem)
			}
			ready := make(chan struct{})
			p := &Proxy{
				outboundAddr: fmt.Sprintf("127.0.0.1:%d", outPort),
				inboundAddr:  fmt.Sprintf("127.0.0.1:%d", inPort),
				serverTLS:    serverTLS,
				clientTLS:    clientTLS,
				nodeIP:       "127.0.0.1",
				inboundPort:  inPort,
				resolver:     &staticResolver{nodeIP: "127.0.0.1"},
				origDstFunc: func(net.Conn) (string, error) {
					<-hold
					return "", errors.New("held connection released")
				},
				logger:         testLogger(),
				metrics:        m,
				bufPool:        newBufPool(0),
				connSem:        sem,
				maxConnsPerSrc: tc.perSrc,
				drainTimeout:   200 * time.Millisecond,
				onReady:        func() { close(ready) },
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runDone := make(chan error, 1)
			go func() { runDone <- p.Run(ctx) }()
			select {
			case <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("proxy never became ready")
			}

			conn1, err := net.Dial("tcp", p.outboundAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn1.Close()
			// Wait until the first handler is actually holding its slot.
			assertEventually(t, 5*time.Second, func() bool {
				return testutil.ToFloat64(m.activeConnections.WithLabelValues("outbound")) >= 1
			}, "first connection never reached the handler")

			conn2, err := net.Dial("tcp", p.outboundAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn2.Close()
			assertEventually(t, 5*time.Second, func() bool { return tc.counter(m) >= 1 }, "limit rejection never counted")

			releaseHold()
			cancel()
			select {
			case <-runDone:
			case <-time.After(10 * time.Second):
				t.Fatal("proxy Run did not stop")
			}
		})
	}
}
