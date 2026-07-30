package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// certWithWindow mints a self-signed certificate carrying the attestation
// extension (the shape of CDS's identity) with the given validity window.
func certWithWindow(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	attExt, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(11),
		Subject:         pkix.Name{CommonName: "cds"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{attExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func certPolicyOutcome(t *testing.T, cert *x509.Certificate) Outcome {
	t.Helper()
	ev, err := evidenceFromCert(cert, "test")
	if err != nil {
		t.Fatal(err)
	}
	oc := Outcome{Verified: true}
	applyCertificatePolicy(&oc, ev)
	return oc
}

// A currently valid, correctly self-signed certificate sails through.
func TestCertificatePolicyAcceptsValidWindow(t *testing.T) {
	oc := certPolicyOutcome(t, certWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	if !oc.Verified {
		t.Fatalf("valid certificate demoted: %s", oc.Error)
	}
}

// Expiry is the only bound on replaying an old-but-genuine certificate, so an
// expired one must demote the verdict even though its hardware evidence and
// self-signature are internally consistent.
func TestCertificatePolicyRejectsExpired(t *testing.T) {
	oc := certPolicyOutcome(t, certWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)))
	if oc.Verified {
		t.Fatal("expired certificate verified")
	}
	if !strings.Contains(oc.Error, "expired") {
		t.Fatalf("error = %q, want it to name expiry", oc.Error)
	}
}

// Future-dated beyond clock skew is refused; within the skew allowance it is
// accepted, so an issuer marginally ahead of this clock does not false-fail.
func TestCertificatePolicyNotBeforeSkew(t *testing.T) {
	oc := certPolicyOutcome(t, certWithWindow(t, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)))
	if oc.Verified {
		t.Fatal("future-dated certificate verified")
	}
	if !strings.Contains(oc.Error, "not yet valid") {
		t.Fatalf("error = %q, want it to say not yet valid", oc.Error)
	}

	within := certPolicyOutcome(t, certWithWindow(t, time.Now().Add(notBeforeSkew/2), time.Now().Add(time.Hour)))
	if !within.Verified {
		t.Fatalf("certificate within skew allowance demoted: %s", within.Error)
	}
}

// The window is only worth reading because the self-signature covers it: a
// certificate whose body no longer verifies under its own (attested) key is
// refused before its dates are believed.
func TestCertificatePolicyRejectsTamperedBody(t *testing.T) {
	cert := certWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cert.Signature[len(cert.Signature)-1] ^= 0x01
	oc := certPolicyOutcome(t, cert)
	if oc.Verified {
		t.Fatal("certificate with a broken self-signature verified")
	}
	if !strings.Contains(oc.Error, "self-signed") {
		t.Fatalf("error = %q, want it to name the self-signature", oc.Error)
	}
}

// A mesh-signed (non-self-signed) leaf skips the self-signature check — its
// body is authenticated by the chain instead — but its window is still
// enforced: an expired leaf must not verify.
func TestCertificatePolicyRejectsExpiredMeshLeaf(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mesh ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	attExt, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-2 * time.Hour),
		NotAfter:        time.Now().Add(-time.Hour),
		ExtraExtensions: []pkix.Extension{attExt},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	oc := certPolicyOutcome(t, leaf)
	if oc.Verified {
		t.Fatal("expired mesh-signed leaf verified")
	}
	if !strings.Contains(oc.Error, "expired") {
		t.Fatalf("error = %q, want it to name expiry", oc.Error)
	}
}

// The policy only ever demotes: a failed hardware verdict stays failed with
// its original error, and non-certificate evidence is untouched.
func TestCertificatePolicyOnlyDemotes(t *testing.T) {
	cert := certWithWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	ev, err := evidenceFromCert(cert, "test")
	if err != nil {
		t.Fatal(err)
	}
	oc := Outcome{Verified: false, Error: "hardware evidence failed"}
	applyCertificatePolicy(&oc, ev)
	if oc.Verified || oc.Error != "hardware evidence failed" {
		t.Fatalf("policy rewrote a failed verdict: verified=%v error=%q", oc.Verified, oc.Error)
	}

	noLeaf := Outcome{Verified: true}
	applyCertificatePolicy(&noLeaf, &evidence{})
	if !noLeaf.Verified {
		t.Fatal("policy demoted evidence with no certificate")
	}
}
