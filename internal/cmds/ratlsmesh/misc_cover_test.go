//go:build linux

package ratlsmesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls/cdsclient"
)

func TestHealthServerServe(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, time.Second, time.Second)
	h.ready.Store(true)
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- h.serve(ctx, fmt.Sprintf("127.0.0.1:%d", port)) }()

	assertEventually(t, 5*time.Second, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "health serve never answered /live")

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve() = %v, want nil after shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop on cancel")
	}

	// A second serve on an already-bound port errors immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := h.serve(context.Background(), ln.Addr().String()); err == nil {
		t.Fatal("serve on a bound port should error")
	}
}

func TestHealthReadyCertProvisioningGates(t *testing.T) {
	_, mgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		CertTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name           string
		server, client *ratls.CertManager
	}{
		{"server cert not provisioned", mgr, nil},
		{"client cert not provisioned", nil, mgr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHealthServer(testMetrics(), tc.server, tc.client, 10, time.Second, time.Second)
			h.ready.Store(true)
			rec := httptest.NewRecorder()
			h.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if mgr.CertReady() {
				t.Skip("cert manager unexpectedly pre-provisioned")
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "not provisioned") {
				t.Errorf("body = %q", rec.Body.String())
			}
		})
	}
}

func TestNtohs(t *testing.T) {
	kernel := [2]byte{0x1f, 0x90} // 8080 in network byte order
	n := binary.NativeEndian.Uint16(kernel[:])
	if got := ntohs(n); got != 8080 {
		t.Errorf("ntohs = %d, want 8080", got)
	}
}

func TestIfaceAllowed(t *testing.T) {
	if !ifaceAllowed("cni0", []string{"lo", "cni0"}) {
		t.Error("cni0 should be allowed")
	}
	if ifaceAllowed("eth0", []string{"lo", "cni0"}) {
		t.Error("eth0 should not be allowed")
	}
}

func TestDefaultLocalRouteCheck(t *testing.T) {
	if ok, err := defaultLocalRouteCheck("10.0.0.1", nil); ok || err != nil {
		t.Errorf("empty allowlist: got (%v,%v), want (false,nil)", ok, err)
	}
	if ok, err := defaultLocalRouteCheck("not-an-ip", []string{"lo"}); ok || err != nil {
		t.Errorf("bad IP: got (%v,%v), want (false,nil)", ok, err)
	}
	// The kernel routes 127.0.0.1 via lo. Netlink route-get is read-only and
	// works unprivileged; tolerate environments where it does not.
	ok, err := defaultLocalRouteCheck("127.0.0.1", []string{"lo"})
	if err == nil && !ok {
		t.Error("route to 127.0.0.1 should use lo")
	}
	if ok2, err2 := defaultLocalRouteCheck("127.0.0.1", []string{"cni0"}); err2 == nil && ok2 {
		t.Error("route to 127.0.0.1 should not match cni0-only allowlist")
	}
}

func TestAddrIP(t *testing.T) {
	ipn := &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}
	if got := addrIP(ipn); !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("addrIP(IPNet) = %v", got)
	}
	ipa := &net.IPAddr{IP: net.ParseIP("fd00::1")}
	if got := addrIP(ipa); !got.Equal(net.ParseIP("fd00::1")) {
		t.Errorf("addrIP(IPAddr) = %v", got)
	}
	if got := addrIP(&net.TCPAddr{IP: net.ParseIP("10.0.0.1")}); got != nil {
		t.Errorf("addrIP(TCPAddr) = %v, want nil", got)
	}
}

func TestRunLocalCIDRRefreshLoop(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.244.0.0/24")
	r := &k8sResolver{
		nodeIP:          "10.0.0.1",
		logger:          testLogger(),
		podMap:          map[string]podEntry{},
		localRouteCheck: passthroughLocalRouteCheck,
		localCIDRSource: func(string) ([]localCIDR, error) {
			return testLocalCIDRs(cidr), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.runLocalCIDRRefreshLoop(ctx, 5*time.Millisecond)
		close(done)
	}()
	assertEventually(t, 5*time.Second, func() bool { return r.LocalCIDRCount() == 1 }, "refresh loop never reconciled")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh loop did not stop on cancel")
	}
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

func TestInGuestResolverInvalidIPs(t *testing.T) {
	r := &inGuestResolver{podIP: "10.42.0.5"}
	if node, local := r.Resolve("not-an-ip"); node != "not-an-ip" || local {
		t.Errorf("Resolve(bad) = (%q,%v)", node, local)
	}
	if r.ValidateLocalDest("not-an-ip") {
		t.Error("ValidateLocalDest(bad) = true")
	}
}

func TestRecordOutboundDestRejectedUnknownReason(t *testing.T) {
	m := testMetrics()
	m.recordOutboundDestRejected("some-new-reason")
	if got := testutil.ToFloat64(m.outboundDestRejected.WithLabelValues(outboundRejectUnknownPod)); got != 1 {
		t.Errorf("unknown reason not folded into unknown_pod bucket: %v", got)
	}
}

func TestRunInGuestConfigErrors(t *testing.T) {
	valid := func() inGuestConfig {
		c := defaultInGuestConfig()
		c.workloadID = "wl"
		c.cdsURL = "http://127.0.0.1:1"
		c.attestationServiceURL = defaultInGuestAttestationServiceURL
		c.podIP = "10.42.0.9"
		return c
	}

	t.Run("bad log level", func(t *testing.T) {
		c := valid()
		c.logLevel = "shouty"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), envLogLevel) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("validate failure", func(t *testing.T) {
		c := valid()
		c.workloadID = ""
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), envWorkloadID) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad pod IP", func(t *testing.T) {
		c := valid()
		c.podIP = "not-an-ip"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), "resolve pod IP") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("iptables setup failure", func(t *testing.T) {
		// PATH without any iptables binary.
		t.Setenv("PATH", t.TempDir())
		c := valid()
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), "in-guest iptables setup") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRunCDSUpgradeProviderError(t *testing.T) {
	// A config missing NodeIP makes provider creation fail; run
	// must log and return rather than panic or retry.
	c := defaultInGuestConfig()
	badCfg := &cdsclient.Config{
		CDSURL:            "http://127.0.0.1:1",
		AttestationApiURL: "http://127.0.0.1:1",
		CDSCAURL:          "http://127.0.0.1:1",
		// NodeIP intentionally missing.
	}
	// run is synchronous; a hang here is caught by the test binary timeout.
	cdsUpgrade{
		logger:          testLogger(),
		logPrefix:       "in-guest cds",
		newProvider:     func() (*cdsclient.Provider, error) { return cdsclient.NewProvider(badCfg, testLogger()) },
		retryBackoff:    c.cdsRetryBackoff,
		retryMaxBackoff: c.cdsRetryMaxBackoff,
		opTimeout:       c.cdsOpTimeout,
		metrics:         testMetrics(),
	}.run(context.Background())
}
