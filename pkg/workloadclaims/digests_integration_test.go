package workloadclaims

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// The callback is otherwise only ever driven through a fake at the CDS
// interface boundary, so nothing exercises the wire: the identity decode, the
// 404 to ErrSandboxUnknown mapping, the response caps, or that the client dials
// DigestsPort rather than anything the caller supplied. This drives a real
// ServeDigests over a real TLS listener with a real DigestsClient transport.
//
// TLS here is a plain self-signed pair, not RA-TLS: attestation needs an
// attestation-api, and what is under test is the protocol above the handshake.
// routableLocalIP is an address the client's own validation accepts — loopback
// is rejected by design, so the test binds where production would: a routable
// interface address.
func routableLocalIP(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || !n.IP.IsGlobalUnicast() {
			continue
		}
		return n.IP
	}
	t.Skip("no routable IPv4 interface address in this environment")
	return nil
}

func serveDigestsTLS(t *testing.T, resolver SandboxResolver, identity []byte) (*DigestsClient, string) {
	t.Helper()
	ip := routableLocalIP(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "inventory"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}

	// DigestsPort is privileged and unbindable in CI, so point the client at an
	// ephemeral one. Everything above the port — the routes, the decode, the
	// status mapping — is exactly what production runs.
	l, err := tls.Listen("tcp", net.JoinHostPort(ip.String(), "0"), &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	prev := dialPort
	dialPort, err = strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialPort = prev })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeDigests(ctx, l, resolver, identity) }()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &DigestsClient{
		timeout: 5 * time.Second,
		http: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		},
	}, ip.String()
}

func TestDigestsCallbackOverTLS(t *testing.T) {
	signer, err := NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{digests: map[string][]string{
		"sandbox-1": {digestA, digestB},
		"sandbox-2": nil,
	}}
	c, host := serveDigestsTLS(t, resolver, signer.PublicKeyDER())
	ctx := context.Background()

	// The key CDS verifies a token against is the one the inventory serves.
	pub, err := c.InventoryKey(ctx, host)
	if err != nil {
		t.Fatalf("InventoryKey: %v", err)
	}
	if !pub.Equal(signer.PublicKey()) {
		t.Fatal("identity route served a key that is not the signer's")
	}

	digests, err := c.Fetch(ctx, host, "sandbox-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(digests) != 2 || digests[0] != digestA || digests[1] != digestB {
		t.Fatalf("digests = %v", digests)
	}

	// A known sandbox with nothing recorded answers [], which CDS treats as
	// fail-closed rather than an empty pass.
	empty, err := c.Fetch(ctx, host, "sandbox-2")
	if err != nil {
		t.Fatalf("Fetch empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("digests = %v, want none", empty)
	}

	// An unknown sandbox is distinguishable from a transport failure.
	if _, err := c.Fetch(ctx, host, "nosuchsandbox"); err != ErrSandboxUnknown {
		t.Fatalf("err = %v, want ErrSandboxUnknown", err)
	}
}

// The client dials DigestsPort and nothing else: the port is not carried in the
// token, so a requester cannot steer the callback at a port of its choosing.
func TestDigestsClientIgnoresCallerSuppliedPort(t *testing.T) {
	signer, err := NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	c, host := serveDigestsTLS(t, &fakeResolver{digests: map[string][]string{"sandbox-1": {digestA}}}, signer.PublicKeyDER())

	// A host:port pair is not a host, and is refused before any dial.
	if _, err := c.Fetch(context.Background(), host+":1", "sandbox-1"); err == nil {
		t.Fatal("Fetch accepted a host:port and may have dialed a caller-chosen port")
	}
}
