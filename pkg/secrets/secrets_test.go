package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestReportDataForFetch(t *testing.T) {
	req := FetchRequest{
		InitContainerDigests: []string{"sha256:aaaa"},
		ResponsePubkey:       "cHVi",
		Requests:             []SecretRequest{{Digest: "sha256:x", Paths: []string{"/secrets/a"}}},
	}
	rd1, err := ReportDataForFetch([]byte("challenge-1"), req)
	if err != nil {
		t.Fatalf("report data: %v", err)
	}
	rd2, _ := ReportDataForFetch([]byte("challenge-1"), req)
	if rd1 != rd2 {
		t.Fatal("not deterministic")
	}
	rd3, _ := ReportDataForFetch([]byte("challenge-2"), req)
	if rd1 == rd3 {
		t.Fatal("challenge not bound")
	}
	req2 := req
	req2.Requests[0].Paths = []string{"/secrets/b"}
	rd4, _ := ReportDataForFetch([]byte("challenge-1"), req2)
	if rd1 == rd4 {
		t.Fatal("request body not bound")
	}
	req3 := req
	req3.ResponsePubkey = "b3RoZXI"
	rd5, _ := ReportDataForFetch([]byte("challenge-1"), req3)
	if rd1 == rd5 {
		t.Fatal("response pubkey not bound")
	}
}

func TestWrapRoundTrip(t *testing.T) {
	priv, pub, err := GenerateX25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	blob, err := Wrap(pub, []byte("model-dek"), []byte("aad-context"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	out, err := Unwrap(priv, []byte("aad-context"), blob)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(out) != "model-dek" {
		t.Fatalf("got %q", out)
	}

	// Wrong AAD fails.
	if _, err := Unwrap(priv, []byte("other"), blob); err == nil {
		t.Fatal("unwrap succeeded with wrong AAD")
	}
	// Wrong key fails.
	priv2, _, _ := GenerateX25519()
	if _, err := Unwrap(priv2, []byte("aad-context"), blob); err == nil {
		t.Fatal("unwrap succeeded with wrong key")
	}
	// Tampered ciphertext fails.
	blob.Ciphertext = base64.StdEncoding.EncodeToString([]byte("tampered-tampered"))
	if _, err := Unwrap(priv, []byte("aad-context"), blob); err == nil {
		t.Fatal("unwrap succeeded with tampered ciphertext")
	}
}

func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

func issueBrokerLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "c8s-secrets-broker"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pemBytes := pemEncode("CERTIFICATE", der)
	return cert, key, pemBytes
}

func TestBrokerIdentityVerify(t *testing.T) {
	ca, caKey := newTestCA(t)
	_, leafKey, leafPEM := issueBrokerLeaf(t, ca, caKey)
	caPEM := pemEncode("CERTIFICATE", ca.Raw)

	_, encPub, err := GenerateX25519()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	sig, err := SignEncryptionPubkey(leafKey, encPub)
	if err != nil {
		t.Fatalf("sign enc: %v", err)
	}
	bi := BrokerIdentity{
		SigningLeafPEM:      leafPEM,
		CAChainPEM:          caPEM,
		EncryptionPubkey:    base64.StdEncoding.EncodeToString(encPub),
		EncryptionPubkeySig: sig,
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	signingPub, gotEnc, err := bi.Verify(roots)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(gotEnc) != string(encPub) {
		t.Fatal("encryption pubkey mismatch")
	}

	// Response sign/verify round trip.
	blob, err := Wrap(encPub, []byte("payload"), nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	rsig, err := SignResponse(leafKey, blob)
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}
	if err := VerifyResponseSignature(signingPub, blob, rsig); err != nil {
		t.Fatalf("verify response: %v", err)
	}
	blob.Ciphertext = base64.StdEncoding.EncodeToString([]byte("tampered"))
	if err := VerifyResponseSignature(signingPub, blob, rsig); err == nil {
		t.Fatal("tampered payload passed signature check")
	}

	// Chain to a different root fails.
	otherCA, _ := newTestCA(t)
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(otherCA)
	if _, _, err := bi.Verify(otherRoots); err == nil {
		t.Fatal("identity verified against the wrong CA")
	}

	// Swapped encryption key fails the binding.
	_, encPub2, _ := GenerateX25519()
	bi.EncryptionPubkey = base64.StdEncoding.EncodeToString(encPub2)
	if _, _, err := bi.Verify(roots); err == nil {
		t.Fatal("swapped encryption pubkey passed")
	}
}
