package workloadproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

type testIdentity struct {
	certFile string
	keyFile  string
	leaf     *x509.Certificate
}

func makeCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func makeIdentity(t *testing.T, dir string, ca testCA, name string, extensionMode string) testIdentity {
	return makeIdentityWithIdentity(t, dir, ca, name, "", extensionMode)
}

func makeIdentityWithIdentity(t *testing.T, dir string, ca testCA, name, stableIdentity, extensionMode string) testIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	validExt, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{
		Name:             name,
		Identity:         stableIdentity,
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	switch extensionMode {
	case "valid":
		tmpl.ExtraExtensions = []pkix.Extension{validExt}
	case "missing":
	case "malformed":
		tmpl.ExtraExtensions = []pkix.Extension{{Id: ratls.OIDMatchedWorkload, Value: []byte{0x30, 0x01}}}
	default:
		t.Fatalf("unknown extension mode %q", extensionMode)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.certPEM...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	base := strings.ReplaceAll(name+"-"+extensionMode, "/", "-")
	certFile := filepath.Join(dir, base+".crt")
	keyFile := filepath.Join(dir, base+".key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return testIdentity{certFile: certFile, keyFile: keyFile, leaf: leaf}
}

func makeSelfSignedIdentity(t *testing.T, dir, name string) testIdentity {
	t.Helper()
	self := makeCA(t, name)
	// A self-signed CA can carry a syntactically valid workload stamp, but it is
	// not trusted by the mesh CA and must still fail.
	ext, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{
		Name: name, AllowlistVersion: "1", AllowlistDigest: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	self.cert.ExtraExtensions = []pkix.Extension{ext}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(self.key)
	certFile := filepath.Join(dir, "self.crt")
	keyFile := filepath.Join(dir, "self.key")
	if err := os.WriteFile(certFile, self.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return testIdentity{certFile: certFile, keyFile: keyFile, leaf: self.cert}
}

func writeCA(t *testing.T, dir, name string, ca testCA) string {
	t.Helper()
	path := filepath.Join(dir, name+"-ca.crt")
	if err := os.WriteFile(path, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseConfig(mode string, id testIdentity, caFile string) config {
	return config{
		mode:             mode,
		listen:           "127.0.0.1:9443",
		upstream:         "127.0.0.1:9444",
		peerPolicy:       "peer",
		certFile:         id.certFile,
		keyFile:          id.keyFile,
		caFile:           caFile,
		dialTimeout:      time.Second,
		handshakeTimeout: time.Second,
		idleTimeout:      time.Second,
		shutdownTimeout:  time.Second,
		maxConnections:   8,
	}
}

func TestValidateConfigRestrictsPlaintextAndBounds(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t, "ca")
	id := makeIdentity(t, dir, ca, "gateway", "valid")
	caFile := writeCA(t, dir, "mesh", ca)

	tests := []struct {
		name string
		cfg  config
		want string
	}{
		{"client valid", baseConfig(modeClient, id, caFile), ""},
		{"server valid", baseConfig(modeServer, id, caFile), ""},
		{"client plaintext not loopback", func() config { c := baseConfig(modeClient, id, caFile); c.listen = "0.0.0.0:9443"; return c }(), "loopback"},
		{"server plaintext target not loopback", func() config { c := baseConfig(modeServer, id, caFile); c.upstream = "10.0.0.8:30000"; return c }(), "loopback"},
		{"server target hostname refused", func() config { c := baseConfig(modeServer, id, caFile); c.upstream = "localhost:30000"; return c }(), "numeric IP"},
		{"missing peer selector", func() config { c := baseConfig(modeClient, id, caFile); c.peerPolicy = ""; return c }(), "exactly one"},
		{"both peer selectors", func() config { c := baseConfig(modeClient, id, caFile); c.peerIdentity = "peer"; return c }(), "exactly one"},
		{"bad peer policy", func() config { c := baseConfig(modeClient, id, caFile); c.peerPolicy = "bad/name"; return c }(), "valid c8s workload"},
		{"bad peer identity", func() config {
			c := baseConfig(modeClient, id, caFile)
			c.peerPolicy = ""
			c.peerIdentity = "bad/name"
			return c
		}(), "valid c8s workload"},
		{"zero timeout", func() config { c := baseConfig(modeClient, id, caFile); c.handshakeTimeout = 0; return c }(), "positive"},
		{"zero connection bound", func() config { c := baseConfig(modeClient, id, caFile); c.maxConnections = 0; return c }(), "between 1 and 65536"},
		{"excessive connection bound", func() config { c := baseConfig(modeClient, id, caFile); c.maxConnections = 65537; return c }(), "between 1 and 65536"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(tc.cfg)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyPeerRequiresCAAndSelectedMatchedWorkloadPin(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t, "mesh")
	otherCA := makeCA(t, "other")
	_, roots, err := loadRoots(writeCA(t, dir, "mesh", ca))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		identity         testIdentity
		expectedPolicy   string
		expectedIdentity string
		wantError        string
	}{
		{"v1 policy", makeIdentity(t, dir, ca, "sglang-router-v1", "valid"), "sglang-router-v1", "", ""},
		{"v1 identity", makeIdentity(t, dir, ca, "sglang-router-v1", "valid"), "", "sglang-router-v1", ""},
		{"v2 policy", makeIdentityWithIdentity(t, dir, ca, "sglang-router-v2", "sglang-router", "valid"), "sglang-router-v2", "", ""},
		{"v2 identity", makeIdentityWithIdentity(t, dir, ca, "sglang-router-v2", "sglang-router", "valid"), "", "sglang-router", ""},
		{"changed policy", makeIdentityWithIdentity(t, dir, ca, "sglang-router-v2", "sglang-router", "valid"), "sglang-router-v1", "", "does not match"},
		{"changed identity", makeIdentityWithIdentity(t, dir, ca, "sglang-router-v2", "sglang-router", "valid"), "", "gateway", "does not match"},
		{"policy substituted for identity", makeIdentityWithIdentity(t, dir, ca, "sglang-router-v2", "sglang-router", "valid"), "", "sglang-router-v2", "does not match"},
		{"missing stamp", makeIdentity(t, dir, ca, "sglang-router-missing", "missing"), "sglang-router-missing", "", "no matched-workload"},
		{"malformed stamp", makeIdentity(t, dir, ca, "sglang-router-malformed", "malformed"), "sglang-router-malformed", "", "unmarshal"},
		{"wrong CA", makeIdentity(t, dir, otherCA, "sglang-router-v1", "valid"), "sglang-router-v1", "", "does not chain"},
	}
	duplicate := makeIdentity(t, dir, ca, "sglang-router", "valid")
	duplicateLeaf := *duplicate.leaf
	for _, ext := range duplicate.leaf.Extensions {
		if ext.Id.Equal(ratls.OIDMatchedWorkload) {
			duplicateLeaf.Extensions = append(duplicateLeaf.Extensions, ext)
			break
		}
	}
	if err := verifyPeer([]*x509.Certificate{&duplicateLeaf}, roots, "sglang-router", "", x509.ExtKeyUsageServerAuth); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("duplicate workload extension error = %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPeer([]*x509.Certificate{tc.identity.leaf}, roots, tc.expectedPolicy, tc.expectedIdentity, x509.ExtKeyUsageServerAuth)
			if tc.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
		})
	}

	self := makeSelfSignedIdentity(t, dir, "sglang-router")
	if err := verifyPeer([]*x509.Certificate{self.leaf}, roots, "sglang-router", "", x509.ExtKeyUsageServerAuth); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("self-signed peer error = %v", err)
	}
}

func startListener(t *testing.T, host string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func startEcho(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln := startListener(t, "127.0.0.1:0")
	var accepted atomic.Int64
	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), &accepted
}

func startEOFReply(t *testing.T) string {
	t.Helper()
	ln := startListener(t, "127.0.0.1:0")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		_, _ = conn.Write(append([]byte("reply:"), request...))
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	return ln.Addr().String()
}

func startTestProxy(t *testing.T, cfg config) string {
	t.Helper()
	ln := startListener(t, "127.0.0.1:0")
	cfg.listen = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, ln, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("proxy did not stop")
		}
	})
	return ln.Addr().String()
}

func TestClientAndServerProxyStreamDuplex(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t, "mesh")
	caFile := writeCA(t, dir, "mesh", ca)
	gateway := makeIdentity(t, dir, ca, "gateway", "valid")
	router := makeIdentity(t, dir, ca, "sglang-router", "valid")
	target, accepted := startEcho(t)

	serverCfg := baseConfig(modeServer, router, caFile)
	serverCfg.upstream = target
	serverCfg.peerPolicy = "gateway"
	serverCfg.idleTimeout = 5 * time.Second
	serverAddr := startTestProxy(t, serverCfg)

	clientCfg := baseConfig(modeClient, gateway, caFile)
	clientCfg.upstream = serverAddr
	clientCfg.peerPolicy = "sglang-router"
	clientCfg.idleTimeout = 5 * time.Second
	clientAddr := startTestProxy(t, clientCfg)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		writeDone <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo size/content mismatch: got %d, want %d", len(got), len(payload))
	}
	if accepted.Load() != 1 {
		t.Fatalf("plaintext target accepts = %d, want 1", accepted.Load())
	}
}

// The policy side remains on a v1 certificate while the identity side moves to
// v2. This is the safe mixed-version migration: each proxy selects the stamp
// field it means to authorize, and half-close still reaches the plaintext peer.
func TestClientAndServerProxyPreserveTLSHalfCloseAcrossV1V2(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t, "mesh")
	caFile := writeCA(t, dir, "mesh", ca)
	gateway := makeIdentity(t, dir, ca, "gateway", "valid")
	router := makeIdentityWithIdentity(t, dir, ca, "sglang-router-v2", "sglang-router", "valid")

	serverCfg := baseConfig(modeServer, router, caFile)
	serverCfg.upstream = startEOFReply(t)
	serverCfg.peerPolicy = "gateway"
	serverCfg.idleTimeout = 5 * time.Second
	serverAddr := startTestProxy(t, serverCfg)

	clientCfg := baseConfig(modeClient, gateway, caFile)
	clientCfg.upstream = serverAddr
	clientCfg.peerPolicy = ""
	clientCfg.peerIdentity = "sglang-router"
	clientCfg.idleTimeout = 5 * time.Second
	clientAddr := startTestProxy(t, clientCfg)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(response), "reply:request"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func TestServerRejectsWrongClientWorkloadBeforePlaintextDial(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t, "mesh")
	caFile := writeCA(t, dir, "mesh", ca)
	intruder := makeIdentity(t, dir, ca, "intruder", "valid")
	router := makeIdentity(t, dir, ca, "sglang-router", "valid")
	target, accepted := startEcho(t)

	serverCfg := baseConfig(modeServer, router, caFile)
	serverCfg.upstream = target
	serverCfg.peerPolicy = "gateway"
	serverAddr := startTestProxy(t, serverCfg)
	clientCfg := baseConfig(modeClient, intruder, caFile)
	clientCfg.upstream = serverAddr
	clientCfg.peerPolicy = "sglang-router"
	clientAddr := startTestProxy(t, clientCfg)

	conn, err := net.DialTimeout("tcp", clientAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte("secret"))
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	_ = conn.Close()
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatalf("plaintext target was reached by wrong client %d time(s)", accepted.Load())
	}
}

func TestClientHandshakeTimeoutClosesPlaintextConnection(t *testing.T) {
	dir := t.TempDir()
	ca := makeCA(t, "mesh")
	caFile := writeCA(t, dir, "mesh", ca)
	gateway := makeIdentity(t, dir, ca, "gateway", "valid")
	stall := startListener(t, "127.0.0.1:0")
	go func() {
		conn, err := stall.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(time.Second)
		}
	}()

	cfg := baseConfig(modeClient, gateway, caFile)
	cfg.upstream = stall.Addr().String()
	cfg.peerPolicy = "sglang-router"
	cfg.handshakeTimeout = 100 * time.Millisecond
	clientAddr := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	start := time.Now()
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("stalled TLS peer did not close the plaintext connection")
	}
	if time.Since(start) > 750*time.Millisecond {
		t.Fatalf("handshake timeout took %s", time.Since(start))
	}
}

func TestReadBoundedRejectsLargeCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.pem")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxCredentialBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readBounded error = %v", err)
	}
}

func TestCommandDoesNotAcceptArguments(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"unexpected"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("workload-proxy accepted a positional argument")
	}
}

func TestRunRejectsHiddenC8sEntrypointBeforeUsingIdentity(t *testing.T) {
	previous := os.Args
	defer func() { os.Args = previous }()
	os.Args = []string{"/c8s", "workload-proxy"}
	err := run(config{})
	if err == nil || !strings.Contains(err.Error(), "argv[0] exactly /workload-proxy") {
		t.Fatalf("run error = %v, want fail-closed entrypoint error", err)
	}
}

func TestValidateEntrypointAcceptsOnlyImageAlias(t *testing.T) {
	if err := validateEntrypoint("/workload-proxy"); err != nil {
		t.Fatal(err)
	}
	for _, argv0 := range []string{"/c8s", "workload-proxy", "/usr/local/bin/workload-proxy", ""} {
		if err := validateEntrypoint(argv0); err == nil {
			t.Fatalf("argv[0] %q was accepted", argv0)
		}
	}
}

// Compile-time checks for the connection types used by the duplex copier.
var _ interface{ CloseWrite() error } = (*idleConn)(nil)
var _ net.Conn = (*idleConn)(nil)
var _ = tls.VersionTLS13
