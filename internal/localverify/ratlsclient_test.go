package localverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ratlsServingCert mints a self-signed serving cert carrying an az-snp
// evidence envelope in the RA-TLS extension, with the given validity window.
func ratlsServingCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := json.Marshal(types.AttestationEvidence{
		Platform: string(types.PlatformAzSnp),
		Evidence: json.RawMessage(`{"hcl_report":"fake"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: embedded}
	ext, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "ratls-peer"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		DNSNames:        []string{"127.0.0.1", "localhost"},
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func tlsServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The handshake authenticates the certificate body before the evidence: an
// expired peer is refused without spending an evidence verification, and a
// currently valid attested peer still passes.
func TestNewRATLSHTTPClientEnforcesPeerCertValidity(t *testing.T) {
	now := time.Now()
	var verifyCalls atomic.Int32
	approve := func(context.Context, string, json.RawMessage, Params) (*teetypes.VerificationResult, error) {
		verifyCalls.Add(1)
		match := true
		return &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &match}, nil
	}

	t.Run("expired peer refused before evidence verification", func(t *testing.T) {
		srv := tlsServer(t, ratlsServingCert(t, now.Add(-2*time.Hour), now.Add(-time.Hour)))
		hc := NewRATLSHTTPClient(nil, approve, time.Second)
		_, err := hc.Get(srv.URL)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want an expiry rejection, got: %v", err)
		}
		if got := verifyCalls.Load(); got != 0 {
			t.Fatalf("an expired peer consumed %d evidence verification(s), want 0", got)
		}
	})

	t.Run("valid attested peer accepted", func(t *testing.T) {
		srv := tlsServer(t, ratlsServingCert(t, now.Add(-time.Hour), now.Add(time.Hour)))
		hc := NewRATLSHTTPClient(nil, approve, time.Second)
		resp, err := hc.Get(srv.URL)
		if err != nil {
			t.Fatalf("valid attested peer refused: %v", err)
		}
		resp.Body.Close()
		if verifyCalls.Load() == 0 {
			t.Fatal("evidence verifier was never consulted for the valid peer")
		}
	})
}

// caSignedRATLSCert mints a CA-issued serving cert carrying a well-formed
// RA-TLS extension: genuine evidence, but a body nothing on this path
// authenticates (issuer != subject, and this client verifies no chain).
func caSignedRATLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "some CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf := ratlsServingCert(t, now.Add(-time.Hour), now.Add(time.Hour))
	tmpl := leaf.Leaf
	tmpl.ExtraExtensions = tmpl.Extensions
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, tmpl.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leaf.PrivateKey, Leaf: parsed}
}

// Peers here are self-signed RA-TLS leaves; this client verifies no chain and
// holds no CA. A CA-vouched leaf therefore arrives with NOTHING having
// authenticated its body — no signature is checked when issuer != subject —
// so its window, subject and stamps are whatever the producer of the bytes
// chose, under a genuine attestation extension. The classification must be
// asserted, not discarded.
func TestNewRATLSHTTPClientRejectsCAVouchedPeer(t *testing.T) {
	var verifyCalls atomic.Int32
	approve := func(context.Context, string, json.RawMessage, Params) (*teetypes.VerificationResult, error) {
		verifyCalls.Add(1)
		match := true
		return &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &match}, nil
	}

	srv := tlsServer(t, caSignedRATLSCert(t))
	hc := NewRATLSHTTPClient(nil, approve, time.Second)
	_, err := hc.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "not self-signed") {
		t.Fatalf("want a body-authentication rejection, got: %v", err)
	}
	if got := verifyCalls.Load(); got != 0 {
		t.Fatalf("a CA-vouched peer consumed %d evidence verification(s), want 0", got)
	}
}

// attestedTLSServer serves over TLS with a (fake-report) RA-TLS attested cert.
func attestedTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// recordingVerify captures what the handshake hands the verifier.
type recordingVerify struct {
	platform     string
	erd          []byte
	measurements [][]byte
	hasDeadline  bool
	err          error
}

func (r *recordingVerify) fn(ctx context.Context, platform string, evidence json.RawMessage, p Params) (*teetypes.VerificationResult, error) {
	r.platform = platform
	r.erd = p.ExpectedReportData
	r.measurements = p.Measurements
	_, r.hasDeadline = ctx.Deadline()
	if r.err != nil {
		return nil, r.err
	}
	return &teetypes.VerificationResult{SignatureValid: true}, nil
}

func TestNewRATLSHTTPClientHandshake(t *testing.T) {
	srv := attestedTLSServer(t)
	measurements := [][]byte{bytes.Repeat([]byte{0x11}, 48)}

	t.Run("attested peer accepted, policy and deadline forwarded", func(t *testing.T) {
		rec := &recordingVerify{}
		client := NewRATLSHTTPClient(measurements, rec.fn, 5*time.Second)
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET through the verifying client: %v", err)
		}
		resp.Body.Close()
		if rec.platform != "snp" {
			t.Errorf("verifier got platform %q, want snp", rec.platform)
		}
		if len(rec.erd) != 48 {
			t.Errorf("verifier got a %d-byte anchor, want the unpadded 48-byte key anchor", len(rec.erd))
		}
		if len(rec.measurements) != 1 || !bytes.Equal(rec.measurements[0], measurements[0]) {
			t.Errorf("measurement pin not forwarded: %x", rec.measurements)
		}
		if !rec.hasDeadline {
			t.Error("verifyTimeout > 0 must bound the verification context with a deadline")
		}
	})

	t.Run("zero verify timeout leaves the context unbounded", func(t *testing.T) {
		rec := &recordingVerify{}
		client := NewRATLSHTTPClient(nil, rec.fn, 0)
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET through the verifying client: %v", err)
		}
		resp.Body.Close()
		if rec.hasDeadline {
			t.Error("verifyTimeout == 0 must not put a deadline on the verification context")
		}
	})

	t.Run("verifier rejection fails the handshake", func(t *testing.T) {
		rec := &recordingVerify{err: errors.New("rejected")}
		client := NewRATLSHTTPClient(nil, rec.fn, 5*time.Second)
		if _, err := client.Get(srv.URL); err == nil {
			t.Fatal("a rejected attestation must fail the request")
		}
	})

	t.Run("unattested peer fails the handshake", func(t *testing.T) {
		plain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer plain.Close()
		rec := &recordingVerify{}
		client := NewRATLSHTTPClient(nil, rec.fn, 5*time.Second)
		if _, err := client.Get(plain.URL); err == nil {
			t.Fatal("a cert without the RA-TLS extension must fail the request")
		}
	})
}

func TestNewRATLSHTTPClientTimeouts(t *testing.T) {
	client := NewRATLSHTTPClient(nil, (&recordingVerify{}).fn, time.Second)
	if client.Timeout != 30*time.Second {
		t.Errorf("client timeout = %v, want 30s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}
	if tr.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("response header timeout = %v, want 10s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 30*time.Second {
		t.Errorf("idle conn timeout = %v, want 30s", tr.IdleConnTimeout)
	}
}
