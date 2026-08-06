package localverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
