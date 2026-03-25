package assamclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

// Logger is a type alias for [ratls.Logger] to avoid requiring callers
// to import both packages.
type Logger = ratls.Logger

// Provider implements ratls.CertProvider using assam attestation and the
// cert-issuer sidecar. Each Provision call performs:
// authenticate -> attest -> obtain cert -> fetch CA -> return CA-signed certificate.
type Provider struct {
	client *Client
	logger Logger
}

// Ensure Provider implements CertProvider at compile time.
var _ ratls.CertProvider = (*Provider)(nil)

// NewProvider creates an assam-backed CertProvider.
func NewProvider(cfg *Config, logger Logger) (*Provider, error) {
	if cfg.AssamURL == "" {
		return nil, fmt.Errorf("assamclient: AssamURL is required")
	}
	if cfg.AttestationServiceURL == "" {
		return nil, fmt.Errorf("assamclient: AttestationServiceURL is required")
	}
	if cfg.CertIssuerURL == "" {
		return nil, fmt.Errorf("assamclient: CertIssuerURL is required")
	}
	if cfg.NodeIP == "" {
		return nil, fmt.Errorf("assamclient: NodeIP is required")
	}
	if net.ParseIP(cfg.NodeIP) == nil {
		return nil, fmt.Errorf("assamclient: NodeIP %q is not a valid IP address", cfg.NodeIP)
	}

	return &Provider{
		client: NewClient(cfg),
		logger: logger,
	}, nil
}

// Provision performs the full assam attestation flow and returns a CA-signed
// TLS certificate along with its effective TTL.
func (p *Provider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	if p.logger != nil {
		p.logger.Info("assamclient: requesting assam-issued certificate")
	}

	key, certPEM, caCertPEM, err := p.client.RequestCert(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: request cert: %w", err)
	}

	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: parse issued cert: %w", err)
	}

	// Parse CA bundle (may contain multiple certs during rotation windows).
	caCerts, err := certutil.ParsePEMCertificates(caCertPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: parse CA cert: %w", err)
	}

	// Verify the issued certificate chains to the CA before using it.
	roots := x509.NewCertPool()
	for _, ca := range caCerts {
		roots.AddCert(ca)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, 0, fmt.Errorf("assamclient: issued cert does not chain to CA: %w", err)
	}

	chain := [][]byte{cert.Raw}
	for _, ca := range caCerts {
		chain = append(chain, ca.Raw)
	}

	tlsCert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        cert,
	}

	ttl := time.Until(cert.NotAfter)
	if ttl <= 0 {
		return nil, 0, fmt.Errorf("assamclient: issued certificate already expired")
	}

	if p.logger != nil {
		p.logger.Info("assamclient: certificate provisioned",
			"subject", cert.Subject.CommonName,
			"ttl", ttl.Round(time.Second),
			"notAfter", cert.NotAfter,
		)
	}

	return tlsCert, ttl, nil
}
