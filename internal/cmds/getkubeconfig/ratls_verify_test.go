package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorPub is a throwaway operator public key PEM for the tests.
func operatorPub(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(mustKeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// attestedCert builds a genuine RA-TLS TDX cert carrying the given evidence
// envelope, bound to the cert's own key (as the real serving path does).
func attestedCert(t *testing.T, envelope types.AttestationEvidence) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: report}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fakeAttestationCLI writes a stub attestation-cli that prints the given claims
// JSON and points ATTESTATION_CLI at it. Lets the tests drive verifyServerCert's
// post-extraction logic deterministically without real hardware.
func fakeAttestationCLI(t *testing.T, claimsJSON string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-attestation-cli")
	script := "#!/bin/sh\ncat >/dev/null\ncat <<'EOF'\n" + claimsJSON + "\nEOF\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ATTESTATION_CLI", bin)
}

func TestVerifyServerCertNoExtension(t *testing.T) {
	// A plain (non-RA-TLS) cert must be rejected before any CLI call.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	err = verifyServerCert(cert, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "ratls:") {
		t.Fatalf("want RA-TLS extraction error, got %v", err)
	}
}

func TestVerifyServerCertRejectsBadReportData(t *testing.T) {
	// The CLI reports the quote is valid but report_data isn't bound to the
	// cert key — a MITM presenting someone else's quote. Must fail closed.
	fakeAttestationCLI(t, `{"signature_valid":true,"report_data_match":false,"claims":{"platform_data":{"rtmr_3":"aa"}}}`)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(cert, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "report_data") {
		t.Fatalf("want report_data binding failure, got %v", err)
	}
}

func TestVerifyServerCertRejectsWrongRTMR3(t *testing.T) {
	// Genuine, key-bound quote, but rtmr_3 doesn't equal H(op_pub): the node
	// wasn't launched to trust this operator. Must fail closed.
	fakeAttestationCLI(t, `{"signature_valid":true,"report_data_match":true,"claims":{"platform_data":{"rtmr_3":"00"}}}`)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(cert, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "RTMR[3] mismatch") {
		t.Fatalf("want RTMR[3] mismatch, got %v", err)
	}
}

func TestVerifyServerCertAccepts(t *testing.T) {
	// Genuine quote, bound to the cert key, rtmr_3 == H(op_pub): accept.
	pub := operatorPub(t)
	want := expectedRTMR3(pub)
	claims := `{"signature_valid":true,"report_data_match":true,"claims":{"platform_data":{"rtmr_3":"` + want + `"}}}`
	fakeAttestationCLI(t, claims)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	if err := verifyServerCert(cert, pub); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
}
