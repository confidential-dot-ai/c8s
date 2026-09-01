package teewebpki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	statepkg "github.com/confidential-dot-ai/c8s/internal/teewebpki"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestInstallCertificateFetchesCurrentCSRAndSendsAuthorizedUpdate(t *testing.T) {
	clusterKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := operatorTestCSR(t, clusterKey, []string{"api.example"})
	root, rootKey, roots := operatorTestCA(t)
	certificate := operatorTestCertificate(t, clusterKey, root, rootKey, []string{"api.example"}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	operatorKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	operatorDER, _ := x509.MarshalECPrivateKey(operatorKey)
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: operatorDER}))
	if err != nil {
		t.Fatal(err)
	}
	verifier := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&operatorKey.PublicKey}, ClockSkew: time.Minute}

	var received statepkg.PublicUpdate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case statepkg.CSRRoute:
			w.Header().Set(statepkg.VersionHeader, "9")
			_, _ = w.Write(csr)
		case statepkg.CertificateRoute:
			body, _ := io.ReadAll(r.Body)
			if err := verifier.Authorize(r, body); err != nil {
				t.Errorf("operator authorization: %v", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Errorf("decode update: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var stderr bytes.Buffer
	err = installCertificateWithClient(context.Background(), &stderr, server.URL, certificate, roots, server.Client(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if received.Version != 9 {
		t.Fatalf("update version = %d, want 9", received.Version)
	}
	if !bytes.Equal(received.CertificatePEM, certificate) {
		t.Fatal("certificate update differs from input chain")
	}
}

func TestInstallCertificateRejectsCertificateForAnotherKey(t *testing.T) {
	clusterKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root, rootKey, roots := operatorTestCA(t)
	csr := operatorTestCSR(t, clusterKey, []string{"api.example"})
	certificate := operatorTestCertificate(t, wrongKey, root, rootKey, []string{"api.example"}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err := validateCertificateForCSR(certificate, csr, roots); err == nil {
		t.Fatal("accepted a certificate for another private key")
	}
}

func TestInstallCertificateRejectsWrongOrExtraDNSNames(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root, rootKey, roots := operatorTestCA(t)
	csr := operatorTestCSR(t, key, []string{"api.example"})
	for _, names := range [][]string{{"other.example"}, {"api.example", "extra.example"}} {
		certificate := operatorTestCertificate(t, key, root, rootKey, names, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err := validateCertificateForCSR(certificate, csr, roots); err == nil {
			t.Fatalf("accepted certificate DNS SANs %v", names)
		}
	}
}

func TestInstallCertificateRejectsEmptyCSRDNSNames(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root, rootKey, roots := operatorTestCA(t)
	csr := operatorTestCSR(t, key, nil)
	certificate := operatorTestCertificate(t, key, root, rootKey, nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err := validateCertificateForCSR(certificate, csr, roots); err == nil {
		t.Fatal("accepted a CSR with no DNS SANs")
	}
}

func TestInstallCertificateRejectsExpiredOrUntrustedChain(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root, rootKey, roots := operatorTestCA(t)
	csr := operatorTestCSR(t, key, []string{"api.example"})
	expired := operatorTestCertificate(t, key, root, rootKey, []string{"api.example"}, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if err := validateCertificateForCSR(expired, csr, roots); err == nil {
		t.Fatal("accepted an expired public certificate")
	}
	otherRoot, otherRootKey, _ := operatorTestCA(t)
	untrusted := operatorTestCertificate(t, key, otherRoot, otherRootKey, []string{"api.example"}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err := validateCertificateForCSR(untrusted, csr, roots); err == nil {
		t.Fatal("accepted a certificate from an untrusted issuer")
	}
}

func TestCertificateOperationsRejectPlaintextInsecureAndUnpinnedEndpoints(t *testing.T) {
	for _, options := range []cdsconn.Options{
		{URL: "http://cds.example", Insecure: true, Measurements: []string{strings.Repeat("a", 96)}},
		{URL: "https://cds.example", Insecure: true, Measurements: []string{strings.Repeat("a", 96)}},
		{URL: "https://cds.example"},
	} {
		if err := requireAttestedPinnedEndpoint(&options); err == nil {
			t.Fatalf("accepted unsafe certificate endpoint %#v", options)
		}
	}
}

func TestInstallCertificateReportsConcurrentStateConflict(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root, rootKey, roots := operatorTestCA(t)
	csr := operatorTestCSR(t, key, []string{"api.example"})
	certificate := operatorTestCertificate(t, key, root, rootKey, []string{"api.example"}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	operatorKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	operatorDER, _ := x509.MarshalECPrivateKey(operatorKey)
	signer, _ := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: operatorDER}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == statepkg.CSRRoute {
			w.Header().Set(statepkg.VersionHeader, "4")
			_, _ = w.Write(csr)
			return
		}
		http.Error(w, "conflict: stale TLS state version", http.StatusConflict)
	}))
	defer server.Close()
	err := installCertificateWithClient(context.Background(), io.Discard, server.URL, certificate, roots, server.Client(), signer)
	if err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("state conflict error = %v", err)
	}
}

func operatorTestCSR(t *testing.T, key *ecdsa.PrivateKey, names []string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: firstName(names)}, DNSNames: names,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func operatorTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator-test-root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return certificate, key, pool
}

func operatorTestCertificate(t *testing.T, key *ecdsa.PrivateKey, root *x509.Certificate, rootKey *ecdsa.PrivateKey, names []string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: firstName(names)}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
