//go:build linux

package ratlsmesh

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"strings"
)

// attestedMeshTLSConfigs returns server and client TLS configs wired like
// runProxy's: both sides mint self-signed RA-TLS certs from testattest
// evidence and verify the peer through the production VerifyPeerCertificate
// against the policy meshVerifyPolicy builds from the measurements string.
func attestedMeshTLSConfigs(t *testing.T, stub *testattest.Stub, measurements string) (server, client *tls.Config) {
	t.Helper()
	attestFunc := makeAttestFunc(attestclient.NewClient(""), stub.URL)

	policy, err := meshVerifyPolicy(stub.URL, measurements, "")
	if err != nil {
		t.Fatal(err)
	}

	server, _, err = ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:     "sev-snp",
		AttestFunc:   attestFunc,
		ClientPolicy: policy,
		CertTTL:      time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, _, err = ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:     policy,
		Platform:   "sev-snp",
		AttestFunc: attestFunc,
		CertTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

// serveAttested drives handshakes on ln until it closes, answering every peer
// that completes the mutual handshake with one "ok" byte.
func serveAttested(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			if _, err := conn.Write([]byte("ok")); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, conn)
		}()
	}
}

// An attested peer completes the mesh handshake: the client accepts the
// server's evidence, and the server's post-handshake byte proves it accepted
// the client's. Both directions run the production VerifyPeerCertificate —
// one /verify call each.
func TestMeshHandshakeAcceptsAttestedPeer(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	stub := testattest.New(t)
	stub.SetVerdict(testattest.PassingVerdict(hex.EncodeToString(measurement)))

	serverTLS, clientTLS := attestedMeshTLSConfigs(t, stub, hex.EncodeToString(measurement))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveAttested(ln)

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("attested peer handshake failed: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("server rejected the attested client: %v", err)
	}

	// Each direction asks the verifier to bind the key its peer presented:
	// the client pins the server's cert key, the server the client's (the
	// TLS 1.3 server cert flight comes first, fixing the request order).
	serverKey := conn.ConnectionState().PeerCertificates[0].PublicKey
	clientCert, err := clientTLS.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	clientLeaf, err := x509.ParseCertificate(clientCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	reqs := stub.VerifyRequests()
	if len(reqs) != 2 {
		t.Fatalf("/verify calls = %d, want 2 (one per direction)", len(reqs))
	}
	for i, key := range []crypto.PublicKey{serverKey, clientLeaf.PublicKey} {
		want, err := ratls.ReportDataForKey(key, nil)
		if err != nil {
			t.Fatal(err)
		}
		if reqs[i].Params == nil || reqs[i].Params.ExpectedReportData == nil {
			t.Fatalf("/verify call %d: missing expected report data", i)
		}
		if got := reqs[i].Params.ExpectedReportData.Bytes(); !bytes.Equal(got, want[:]) {
			t.Fatalf("/verify call %d: expected_report_data = %x, want %x (peer key binding)", i, got, want[:])
		}
	}
}

// The same handshake with the verifier reporting a launch_digest outside the
// pinned set fails with a typed policy error, not a generic TLS alert.
func TestMeshHandshakeRejectsUnpinnedMeasurement(t *testing.T) {
	served := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	pinned := bytes.Repeat([]byte{0x99}, ratls.SNPMeasurementSize)
	stub := testattest.New(t)
	stub.SetVerdict(testattest.PassingVerdict(hex.EncodeToString(served)))

	serverTLS, clientTLS := attestedMeshTLSConfigs(t, stub, hex.EncodeToString(pinned))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveAttested(ln)

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err == nil {
		conn.Close()
		t.Fatal("handshake with an unpinned launch measurement succeeded")
	}
	if !errors.Is(err, ratls.ErrPolicyViolation) {
		t.Fatalf("handshake error = %v, want ErrPolicyViolation", err)
	}
}

// meshVerifyPolicy must carry the --rtmrs pins into the policy the handshake
// enforces, and refuse a malformed pin outright.
func TestMeshVerifyPolicyParsesRTMRPins(t *testing.T) {
	hex48 := strings.Repeat("ab", 48)
	policy, err := meshVerifyPolicy("http://127.0.0.1:8400", "", "1="+hex48+",2="+hex48)
	if err != nil {
		t.Fatalf("meshVerifyPolicy: %v", err)
	}
	if len(policy.RTMRs) != 2 {
		t.Fatalf("policy.RTMRs = %v, want RTMR[1] and RTMR[2]", policy.RTMRs)
	}
	if _, err := meshVerifyPolicy("http://127.0.0.1:8400", "", "0="+hex48); err == nil {
		t.Fatal("RTMR[0] pin accepted; it varies with the pod shape and must be refused")
	}
}
