// Package assamclient implements certificate provisioning via the assam
// attestation service. It performs the attestation flow:
// authenticate -> attest -> obtain certificate, and fetches the CA bundle
// from the cert-issuer for chain building.
package assamclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
)

// Config for the assam attestation client.
type Config struct {
	// AssamURL is the base URL of the assam service
	// (e.g., "http://assam.tee-attestation.svc:8080").
	AssamURL string

	// AttestationServiceURL is the URL of the local attestation service
	// used by assam to generate TEE evidence
	// (e.g., "http://localhost:8400").
	AttestationServiceURL string

	// AttestationServiceAPIKey is the bearer token for authenticating
	// with the attestation service. Empty means no authentication.
	AttestationServiceAPIKey string

	// CertIssuerURL is the base URL of the cert-issuer sidecar for CA
	// bundle retrieval (e.g., "http://assam.tee-attestation.svc:8090").
	CertIssuerURL string

	// NodeIP is this node's IP for the certificate subject/SAN.
	NodeIP string

	// NodeName is this node's hostname for the certificate subject.
	NodeName string

	// HTTPClient is an optional HTTP client. If nil, a default with
	// sensible timeouts is used.
	HTTPClient *http.Client
}

// defaultTransport returns an http.Transport with sensible timeouts
// for communicating with assam and cert-issuer (cluster-internal services).
func defaultTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          10,
		MaxConnsPerHost:       5,
	}
}

// Client handles certificate provisioning via assam.
type Client struct {
	cfg         *Config
	httpClient  *http.Client
	assamClient attestclient.Client
}

// NewClient creates an assam attestation client.
func NewClient(cfg *Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: defaultTransport(),
		}
	}
	return &Client{
		cfg:         cfg,
		httpClient:  httpClient,
		assamClient: attestclient.NewClientWithHTTPAndAPIKey(cfg.AssamURL, httpClient, cfg.AttestationServiceAPIKey),
	}
}

// RequestCert performs the full assam attestation + certificate issuance flow:
// 1. Generate ECDSA keypair + CSR
// 2. Call assam (authenticate -> attest) to get a signed certificate
// 3. Fetch CA certificate from cert-issuer
// 4. Return key + cert + CA cert
func (c *Client) RequestCert(ctx context.Context) (*ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	csrPEM, err := c.createCSR(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	certPEM, err := c.assamClient.ObtainCertificate(c.cfg.AttestationServiceURL, csrPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("assam attestation: %w", err)
	}

	// Fetch CA certificate from cert-issuer for chain building.
	caCertPEM, err := c.fetchCACertPEM(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch CA cert: %w", err)
	}

	return key, []byte(certPEM), caCertPEM, nil
}

// RefreshCABundle fetches the CA certificate bundle from the cert-issuer's
// /v1/ca endpoint. Returns all certificates in the bundle (supports
// multi-PEM for rotation windows).
func (c *Client) RefreshCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	pemData, err := c.fetchCACertPEM(ctx)
	if err != nil {
		return nil, err
	}
	certs, err := certutil.ParsePEMCertificates(pemData)
	if err != nil {
		return nil, fmt.Errorf("CA bundle: %w", err)
	}
	return certs, nil
}

func (c *Client) createCSR(key *ecdsa.PrivateKey) (string, error) {
	cn := fmt.Sprintf("ratls-mesh-%s", c.cfg.NodeIP)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Lunal"},
		},
		IPAddresses: []net.IP{net.ParseIP(c.cfg.NodeIP)},
	}
	if c.cfg.NodeName != "" {
		tmpl.DNSNames = []string{c.cfg.NodeName}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func (c *Client) fetchCACertPEM(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.CertIssuerURL+"/v1/ca", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET /v1/ca returned %d: %s", resp.StatusCode, body)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}
