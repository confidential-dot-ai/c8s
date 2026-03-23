package ratls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// CertProvider abstracts certificate provisioning. Implementations handle
// key generation, attestation, and certificate creation/signing.
//
// The returned time.Duration is the effective TTL so certState knows when to
// schedule rotation (at 50% of the TTL). Returning 0 means the caller should
// fall back to the configured default TTL.
type CertProvider interface {
	Provision(ctx context.Context) (*tls.Certificate, time.Duration, error)
}

// SelfSignedProvider provisions self-signed RA-TLS certificates using local
// hardware attestation. This is the default provider — it wraps the existing
// provisionCert() logic behind the CertProvider interface.
type SelfSignedProvider struct {
	Platform   string
	AttestFunc func(ctx context.Context, customData string) (string, error)
	Opts       *CertOptions
}

// Provision generates a key, obtains hardware attestation, and creates a
// self-signed certificate with the attestation embedded as an X.509 extension.
func (p *SelfSignedProvider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	key, _, err := GenerateKeyPair()
	if err != nil {
		return nil, 0, err
	}

	teeType, err := parseTEEType(p.Platform)
	if err != nil {
		return nil, 0, err
	}

	reportData, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		return nil, 0, err
	}

	customData := fmt.Sprintf("%x", reportData[:])
	evidence, err := p.AttestFunc(ctx, customData)
	if err != nil {
		return nil, 0, fmt.Errorf("ratls: get attestation: %w", err)
	}

	att := &Attestation{TEEType: teeType, Report: []byte(evidence)}
	certDER, err := CreateAttestedCert(key, att, p.Opts)
	if err != nil {
		return nil, 0, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, 0, fmt.Errorf("ratls: parse issued cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}, p.Opts.ttl(), nil
}
