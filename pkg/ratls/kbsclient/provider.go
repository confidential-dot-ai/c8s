package kbsclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

// Logger is a type alias for [ratls.Logger] to avoid requiring callers
// to import both packages.
type Logger = ratls.Logger

// Provider implements ratls.CertProvider using KBS attestation and the
// cert-issuer sidecar. Each Provision call performs:
// auth → attest → sign-csr → return CA-signed certificate.
type Provider struct {
	client *Client
	logger Logger
}

// Ensure Provider implements CertProvider at compile time.
var _ ratls.CertProvider = (*Provider)(nil)

// NewProvider creates a KBS-backed CertProvider.
func NewProvider(cfg *Config, logger Logger) (*Provider, error) {
	if cfg.KBSURL == "" {
		return nil, fmt.Errorf("kbsclient: KBSURL is required")
	}
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("kbsclient: IssuerURL is required")
	}
	if cfg.TEEType == "" {
		return nil, fmt.Errorf("kbsclient: TEEType is required (e.g. az-snp-vtpm, snp, tdx)")
	}
	if cfg.AttestFunc == nil {
		return nil, fmt.Errorf("kbsclient: AttestFunc is required")
	}
	if cfg.NodeIP == "" {
		return nil, fmt.Errorf("kbsclient: NodeIP is required")
	}

	return &Provider{
		client: NewClient(cfg),
		logger: logger,
	}, nil
}

// Provision performs the full KBS attestation flow and returns a CA-signed
// TLS certificate along with its effective TTL.
func (p *Provider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	if p.logger != nil {
		p.logger.Info("kbsclient: requesting KBS-issued certificate")
	}

	key, certPEM, caCertPEM, err := p.client.RequestCert(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("kbsclient: request cert: %w", err)
	}

	// Parse the issued certificate.
	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("kbsclient: parse issued cert: %w", err)
	}

	// Parse and validate CA certificate.
	caCert, err := certutil.ParseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("kbsclient: parse CA cert: %w", err)
	}

	// Verify the issued certificate chains to the CA before using it.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, 0, fmt.Errorf("kbsclient: issued cert does not chain to CA: %w", err)
	}

	// Build the certificate chain: leaf + CA.
	chain := [][]byte{cert.Raw, caCert.Raw}

	tlsCert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        cert,
	}

	// Compute effective TTL from the certificate validity period.
	ttl := time.Until(cert.NotAfter)
	if ttl <= 0 {
		return nil, 0, fmt.Errorf("kbsclient: issued certificate already expired")
	}

	if p.logger != nil {
		p.logger.Info("kbsclient: KBS-issued certificate provisioned",
			"subject", cert.Subject.CommonName,
			"ttl", ttl.Round(time.Second),
			"notAfter", cert.NotAfter,
		)
	}

	return tlsCert, ttl, nil
}

// CACert returns the KBS CA certificate (fetched and cached from GET /v1/ca).
func (p *Provider) CACert(ctx context.Context) (*x509.Certificate, error) {
	return p.client.CACert(ctx)
}
