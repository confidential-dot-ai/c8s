//go:build linux

package ratlsmesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const transportMeasurement = "424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242"

type transportResolver struct {
	localPodIP string
}

func (r transportResolver) Resolve(string) (nodeIP string, local bool) { return "127.0.0.1", false }
func (r transportResolver) ValidateOutboundDest(ip string) (bool, string) {
	return ip == r.localPodIP, "unknown_pod"
}
func (r transportResolver) ValidateLocalDest(ip string) bool { return ip == r.localPodIP }

func transportListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func transportBackend(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln := transportListener(t)
	accepted := new(atomic.Int64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			request, _ := io.ReadAll(conn)
			_, _ = conn.Write(request)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), accepted
}

func transportTLS(t *testing.T, pins string) (*tls.Config, *tls.Config) {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(transportMeasurement))
	return attestedMeshTLSConfigs(t, stub, pins)
}

func recordTransportVerification(config *tls.Config) <-chan error {
	verdicts := make(chan error, 1)
	verify := config.VerifyPeerCertificate
	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		err := verify(rawCerts, verifiedChains)
		select {
		case verdicts <- err:
		default:
		}
		return err
	}
	return verdicts
}

func requireTransportPolicyRejection(t *testing.T, verdicts <-chan error) {
	t.Helper()
	select {
	case err := <-verdicts:
		if !errors.Is(err, ratls.ErrPolicyViolation) {
			t.Fatalf("peer verification = %v, want ErrPolicyViolation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer verification did not run")
	}
}

func startTransportProxy(t *testing.T, p *Proxy) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(chan struct{})
	p.onReady = func() { close(ready) }
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = p.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if runErr != nil {
				t.Error(runErr)
			}
		case <-time.After(10 * time.Second):
			t.Error("transport proxy did not stop")
		}
	})
	select {
	case <-ready:
	case <-done:
		t.Fatalf("transport proxy stopped before readiness: %v", runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("transport proxy listeners did not become ready")
	}
}

func transportProxy(t *testing.T, serverTLS, clientTLS *tls.Config) *Proxy {
	t.Helper()
	return &Proxy{delivery: hostNetworkDelivery{},
		outboundLn: transportListener(t), inboundLn: transportListener(t),
		serverTLS: serverTLS, clientTLS: clientTLS,
		resolver: transportResolver{localPodIP: "127.0.0.1"},
		logger:   testLogger(), metrics: testMetrics(),
		drainTimeout: 5 * time.Second,
	}
}

func transportDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func awaitTransportCounter(t *testing.T, counter prometheus.Counter) {
	t.Helper()
	assertEventually(t, 5*time.Second, func() bool {
		return testutil.ToFloat64(counter) == 1
	}, "transport outcome was not counted exactly once")
}

// The destination is injected; these tests exercise transport, not interception.
func TestNodeTransportUnitRelaysThroughAttestedProxies(t *testing.T) {
	backend, accepted := transportBackend(t)
	serverTLS, clientTLS := transportTLS(t, transportMeasurement)
	destination := transportProxy(t, serverTLS, clientTLS)
	startTransportProxy(t, destination)
	source := transportProxy(t, serverTLS, clientTLS)
	source.inboundPort = destination.inboundLn.Addr().(*net.TCPAddr).Port
	source.origDstFunc = func(net.Conn) (string, error) { return backend, nil }
	startTransportProxy(t, source)

	conn := transportDial(t, source.outboundLn.Addr().String())
	payload := "attested node transport request and response"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != payload {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	_ = conn.Close()
	awaitTransportCounter(t, source.metrics.connectionsTotal.WithLabelValues("outbound", "success"))
	awaitTransportCounter(t, destination.metrics.connectionsTotal.WithLabelValues("inbound", "success"))
	if accepted.Load() != 1 {
		t.Fatalf("backend accepted %d connections, want 1", accepted.Load())
	}
}

func TestNodeTransportUnitRejectsUnpinnedServer(t *testing.T) {
	backend, accepted := transportBackend(t)
	serverTLS, _ := transportTLS(t, transportMeasurement)
	_, clientTLS := transportTLS(t, strings.Repeat("99", 48))
	verdicts := recordTransportVerification(clientTLS)
	destination := transportProxy(t, serverTLS, clientTLS)
	startTransportProxy(t, destination)
	source := transportProxy(t, serverTLS, clientTLS)
	source.inboundPort = destination.inboundLn.Addr().(*net.TCPAddr).Port
	source.origDstFunc = func(net.Conn) (string, error) { return backend, nil }
	startTransportProxy(t, source)
	conn := transportDial(t, source.outboundLn.Addr().String())
	_, _ = io.WriteString(conn, "must not reach backend")
	_, _ = io.Copy(io.Discard, conn)
	requireTransportPolicyRejection(t, verdicts)
	awaitTransportCounter(t, source.metrics.tlsDialFailures)
	awaitTransportCounter(t, source.metrics.connectionsTotal.WithLabelValues("outbound", "error"))
	if accepted.Load() != 0 {
		t.Fatal("unpinned server received an application connection")
	}
}

func TestNodeTransportUnitRejectsUnpinnedClient(t *testing.T) {
	backend, accepted := transportBackend(t)
	serverTLS, _ := transportTLS(t, strings.Repeat("99", 48))
	verdicts := recordTransportVerification(serverTLS)
	_, clientTLS := transportTLS(t, transportMeasurement)
	destination := transportProxy(t, serverTLS, clientTLS)
	startTransportProxy(t, destination)
	conn := tls.Client(transportDial(t, destination.inboundLn.Addr().String()), clientTLS)
	_, _ = fmt.Fprintf(conn, "%s\nmust not reach backend", backend)
	_, _ = io.Copy(io.Discard, conn)
	requireTransportPolicyRejection(t, verdicts)
	awaitTransportCounter(t, destination.metrics.destHeaderErrors.WithLabelValues("read"))
	if accepted.Load() != 0 {
		t.Fatal("unpinned client reached the backend")
	}
}

func TestNodeTransportUnitRejectsPlaintext(t *testing.T) {
	backend, accepted := transportBackend(t)
	serverTLS, clientTLS := transportTLS(t, transportMeasurement)
	destination := transportProxy(t, serverTLS, clientTLS)
	startTransportProxy(t, destination)
	conn := transportDial(t, destination.inboundLn.Addr().String())
	_, _ = fmt.Fprintf(conn, "%s\nmust not reach backend", backend)
	_, _ = io.Copy(io.Discard, conn)
	awaitTransportCounter(t, destination.metrics.destHeaderErrors.WithLabelValues("read"))
	if accepted.Load() != 0 {
		t.Fatal("plaintext reached the backend")
	}
}

func TestNodeTransportUnitRejectsInvalidDestination(t *testing.T) {
	serverTLS, clientTLS := transportTLS(t, transportMeasurement)
	destination := transportProxy(t, serverTLS, clientTLS)
	startTransportProxy(t, destination)
	conn := tls.Client(transportDial(t, destination.inboundLn.Addr().String()), clientTLS)
	if _, err := io.WriteString(conn, "invalid-destination\nmust not reach backend"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, conn)
	awaitTransportCounter(t, destination.metrics.destHeaderErrors.WithLabelValues("read"))
}

func TestNodeTransportUnitRejectsNonlocalDestination(t *testing.T) {
	backend, accepted := transportBackend(t)
	serverTLS, clientTLS := transportTLS(t, transportMeasurement)
	destination := transportProxy(t, serverTLS, clientTLS)
	destination.resolver = transportResolver{localPodIP: "192.0.2.1"}
	startTransportProxy(t, destination)
	conn := tls.Client(transportDial(t, destination.inboundLn.Addr().String()), clientTLS)
	if _, err := fmt.Fprintf(conn, "%s\nmust not reach backend", backend); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, conn)
	awaitTransportCounter(t, destination.metrics.inboundDestRejected)
	if accepted.Load() != 0 {
		t.Fatal("nonlocal destination reached the backend")
	}
}
