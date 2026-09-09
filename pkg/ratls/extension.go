// Package ratls binds a TLS key to a TEE with an X.509 certificate extension:
// the attestation report's REPORTDATA is hash(publicKey), so a verified report
// proves the key was generated inside the TEE. The extension itself — wire
// format, parsing, the key binding — lives in attestation-go/ratls; this
// package is the c8s side of it: certificate issuance and lifecycle, the TLS
// server and client configs, the CDS provisioning client, and the policy
// verification that runs over the c8s attestation-api.
package ratls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"time"
)

// DefaultCertTTL is the default certificate lifetime used by both
// [CertOptions] and [ServerConfig] when no TTL is specified.
const DefaultCertTTL = 24 * time.Hour

// publicKeyFromCert extracts and validates the public key from a certificate.
func publicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ratls: unsupported ECDSA curve: %s", pub.Curve.Params().Name)
		}
		return pub, nil
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("ratls: unsupported key type in certificate: %T", pub)
	}
}
