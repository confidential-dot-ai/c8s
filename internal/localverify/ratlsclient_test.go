package localverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

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
