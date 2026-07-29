package getcert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"
)

func parseCertPEM(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCDSIdentityRecorder(t *testing.T) {
	var r cdsIdentityRecorder

	// Nothing observed yet: nil, so the discovery field is omitted and a
	// consumer falls back to reaching CDS directly.
	if d := r.discovery(); d != nil {
		t.Fatalf("discovery before any observation = %+v, want nil", d)
	}
	r.observe(nil)
	if d := r.discovery(); d != nil {
		t.Fatalf("discovery after observe(nil) = %+v, want nil", d)
	}

	cert := parseCertPEM(t, testCertificatePEM(t))
	r.observe(cert)
	d := r.discovery()
	if d == nil {
		t.Fatal("discovery returned nil after a certificate was observed")
	}
	if got := parseCertPEM(t, d.CertificatePEM); !got.Equal(cert) {
		t.Fatal("republished certificate does not round-trip to the observed one")
	}
	sum := sha256.Sum256(cert.Raw)
	if d.CertificateSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("CertificateSHA256 = %s, want %x", d.CertificateSHA256, sum)
	}
	observedAt, err := time.Parse(time.RFC3339, d.ObservedAt)
	if err != nil {
		t.Fatalf("ObservedAt %q is not RFC3339: %v", d.ObservedAt, err)
	}
	if since := time.Since(observedAt); since < 0 || since > time.Minute {
		t.Fatalf("ObservedAt %s is not recent", d.ObservedAt)
	}

	// The latest observation wins — CDS re-issues whenever the live allowlist
	// changes, and the discovery doc must republish the certificate in force.
	cert2 := parseCertPEM(t, testCertificatePEM(t))
	r.observe(cert2)
	if d2 := r.discovery(); d2 == nil || d2.CertificateSHA256 == d.CertificateSHA256 {
		t.Fatal("second observation did not replace the first")
	}
}
