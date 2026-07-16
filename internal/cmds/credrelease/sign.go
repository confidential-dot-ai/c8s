package credrelease

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// RKE2 keeps the CA that signs client certs the apiserver trusts here. The
// baked admin identity (rke2.yaml) is O=system:masters, CN=system:admin signed
// by this CA; the release service issues an operator a cert under the same CA.
const (
	rke2ClientCACert = "/var/lib/rancher/rke2/server/tls/client-ca.crt"
	rke2ClientCAKey  = "/var/lib/rancher/rke2/server/tls/client-ca.key"
)

// clusterCA holds the RKE2 client-signing CA loaded from the guest FS.
type clusterCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte // the CA cert PEM, for the returned kubeconfig's trust anchor
}

// loadClusterCA reads the RKE2 client-CA cert+key. RKE2's client-CA is ECDSA
// P-256 (confirmed on the target), so the key parses as *ecdsa.PrivateKey.
func loadClusterCA() (*clusterCA, error) {
	certPEM, err := os.ReadFile(rke2ClientCACert)
	if err != nil {
		return nil, fmt.Errorf("read client-ca.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(rke2ClientCAKey)
	if err != nil {
		return nil, fmt.Errorf("read client-ca.key: %w", err)
	}

	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("client-ca.crt is not a CERTIFICATE PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client-ca.crt: %w", err)
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("client-ca.key is not PEM")
	}
	key, err := parseECPrivateKey(kb.Bytes, kb.Type)
	if err != nil {
		return nil, fmt.Errorf("parse client-ca.key: %w", err)
	}
	return &clusterCA{cert: cert, key: key, pem: certPEM}, nil
}

// parseECPrivateKey handles the two PEM encodings RKE2 may emit (SEC1 "EC
// PRIVATE KEY" or PKCS#8 "PRIVATE KEY") and asserts the result is ECDSA.
func parseECPrivateKey(der []byte, pemType string) (*ecdsa.PrivateKey, error) {
	if pemType == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(der)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("client-ca.key is %T, want ECDSA", k)
	}
	return ec, nil
}

// signOperatorCert signs csr with the cluster CA, producing a kube CLIENT
// certificate with the requested identity. The caller sets group/CN via
// SignParams — v1 uses O=system:masters (cluster-admin), matching the baked
// admin. TTL is short so the operator re-releases.
type signParams struct {
	csr      *x509.CertificateRequest
	org      string // certificate Subject O -> maps to a Kubernetes group
	cn       string // Subject CN -> the Kubernetes user
	ttl      time.Duration
	serialFn func() (*big.Int, error) // injectable for tests; nil -> crypto/rand
}

func (ca *clusterCA) signOperatorCert(p signParams, now time.Time) (certPEM []byte, err error) {
	if p.csr == nil {
		return nil, fmt.Errorf("nil CSR")
	}
	if err := p.csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR self-signature invalid: %w", err)
	}
	serialFn := p.serialFn
	if serialFn == nil {
		serialFn = randSerial
	}
	serial, err := serialFn()
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   p.cn,
			Organization: []string{p.org},
		},
		NotBefore: now.Add(-1 * time.Minute), // small backdate for clock skew
		NotAfter:  now.Add(p.ttl),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Client auth only — this is a kube client cert, not a serving cert.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, p.csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func randSerial() (*big.Int, error) {
	// 128-bit random serial (RFC 5280 recommends >= 64-bit, unpredictable).
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
