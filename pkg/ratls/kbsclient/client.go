// Package kbsclient implements the KBS (Key Broker Service) attestation
// client for obtaining CA-signed certificates. It performs the attestation
// flow: auth → attest → sign-csr, and returns a tls.Certificate suitable
// for use with the ratls package.
package kbsclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

// defaultTransport returns an http.Transport with sensible timeouts
// for communicating with KBS and cert-issuer (cluster-internal services).
func defaultTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          10,
		MaxConnsPerHost:       5,
	}
}

// rcarProtocolVersion is the RCAR (Remote CVM Attestation for Resources)
// protocol version. Must match what the KBS server expects.
const rcarProtocolVersion = "0.4.0"

// Config for the KBS attestation client.
type Config struct {
	// KBSURL is the base URL of the KBS service
	// (e.g., "http://kbs.tee-attestation.svc:8080").
	KBSURL string

	// IssuerURL is the base URL of the cert-issuer sidecar
	// (e.g., "http://kbs.tee-attestation.svc:8090").
	IssuerURL string

	// TEEType is the TEE type string for the KBS RCAR auth request.
	// Must match the kbs-types Tee enum: "az-snp-vtpm" (Azure SEV-SNP),
	// "snp" (bare-metal SEV-SNP), "tdx" (Intel TDX), etc.
	TEEType string

	// AttestFunc generates hardware attestation evidence given report data.
	AttestFunc func(ctx context.Context, reportData string) (string, error)

	// CertTTL is the requested certificate lifetime.
	CertTTL time.Duration

	// NodeIP is this node's IP for the certificate subject/SAN.
	NodeIP string

	// NodeName is this node's hostname for the certificate subject.
	NodeName string

	// HTTPClient is an optional HTTP client. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// Client handles the KBS attestation protocol for certificate issuance.
type Client struct {
	cfg    *Config
	client *http.Client

	mu          sync.Mutex
	cachedToken string // cached EAR JWT from last attestation

	caCertOnce sync.Once
	caCert     *x509.Certificate
	caCertErr  error
}

// NewClient creates a KBS attestation client.
func NewClient(cfg *Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: defaultTransport(),
		}
	}
	return &Client{cfg: cfg, client: httpClient}
}

// --- RCAR protocol types (must match kbs-types crate serialization). ---

// authRequest is sent to POST /kbs/v0/auth to initiate attestation.
type authRequest struct {
	Version     string         `json:"version"`
	TEE         string         `json:"tee"`
	ExtraParams map[string]any `json:"extra-params"`
}

// challengeResponse from KBS auth endpoint.
type challengeResponse struct {
	Nonce       string          `json:"nonce"`
	ExtraParams json.RawMessage `json:"extra-params"`
}

// teePubKey is a JWK representing the ephemeral ECDH public key.
type teePubKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// runtimeData is bound to attestation evidence via REPORT_DATA.
type runtimeData struct {
	Nonce     string    `json:"nonce"`
	TEEPubKey teePubKey `json:"tee-pubkey"`
}

// compositeEvidence wraps TEE evidence per kbs-types Attestation struct.
type compositeEvidence struct {
	PrimaryEvidence    json.RawMessage `json:"primary_evidence"`
	AdditionalEvidence string          `json:"additional_evidence"`
}

// rcarAttestRequest is sent to POST /kbs/v0/attest.
type rcarAttestRequest struct {
	TEEEvidence compositeEvidence `json:"tee-evidence"`
	RuntimeData runtimeData       `json:"runtime-data"`
}

// attestResponse from KBS attest endpoint.
type attestResponse struct {
	Token string `json:"token"`
}

// signCSRRequest to cert-issuer.
// Type aliases for the shared wire types.
type signCSRRequest = issuerapi.SignCSRRequest
type signCSRResponse = issuerapi.SignCSRResponse

// RequestCert performs the full RCAR attestation + certificate issuance flow:
// 1. RCAR auth → attest to get EAR JWT token
// 2. Generate ECDSA keypair + CSR
// 3. POST /v1/sign-csr to cert-issuer with EAR token + CSR
// 4. Return signed cert + CA cert
func (c *Client) RequestCert(ctx context.Context) (*ecdsa.PrivateKey, []byte, []byte, error) {
	token, err := c.rcarAttest(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	// Cache the token for RefreshCABundle.
	c.mu.Lock()
	c.cachedToken = token
	c.mu.Unlock()

	// Generate keypair + CSR.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	csrPEM, err := c.createCSR(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	// Sign CSR via cert-issuer.
	certPEM, caCertPEM, err := c.signCSR(ctx, token, csrPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign CSR: %w", err)
	}

	return key, certPEM, caCertPEM, nil
}

// CACert fetches the CA certificate from the cert-issuer (cached).
func (c *Client) CACert(ctx context.Context) (*x509.Certificate, error) {
	c.caCertOnce.Do(func() {
		c.caCert, c.caCertErr = c.fetchCACert(ctx)
	})
	return c.caCert, c.caCertErr
}

// ResetCACert clears the cached CA cert so the next CACert() call re-fetches.
func (c *Client) ResetCACert() {
	c.caCertOnce = sync.Once{}
	c.caCert = nil
	c.caCertErr = nil
}

// kbsAuth sends POST /kbs/v0/auth with RCAR protocol fields and extracts
// the session cookie and challenge nonce.
func (c *Client) kbsAuth(ctx context.Context) (*challengeResponse, string, error) {
	body, err := json.Marshal(authRequest{
		Version:     rcarProtocolVersion,
		TEE:         c.cfg.TEEType,
		ExtraParams: make(map[string]any),
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.KBSURL+"/kbs/v0/auth", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", fmt.Errorf("auth returned %d: %s", resp.StatusCode, respBody)
	}

	// Extract session cookie.
	var sessionID string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "kbs-session-id" {
			sessionID = cookie.Value
			break
		}
	}
	if sessionID == "" {
		return nil, "", fmt.Errorf("no kbs-session-id cookie in auth response")
	}

	var challenge challengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return nil, "", fmt.Errorf("decode auth response: %w", err)
	}

	return &challenge, sessionID, nil
}

// kbsAttest sends POST /kbs/v0/attest with the attestation evidence wrapped
// in CompositeEvidence format, the runtime data, and the session cookie.
func (c *Client) kbsAttest(ctx context.Context, sessionID, evidence string, rd runtimeData) (string, error) {
	// Build the composite evidence. The evidence format depends on the
	// attestation binary output: JSON object (starts with '{') or compressed
	// base64 string.
	var primaryEvidence json.RawMessage
	trimmed := strings.TrimSpace(evidence)
	if strings.HasPrefix(trimmed, "{") {
		// Already JSON — use as-is.
		primaryEvidence = json.RawMessage(trimmed)
	} else {
		// String value — quote it for JSON.
		quoted, _ := json.Marshal(trimmed)
		primaryEvidence = quoted
	}

	attestReq := rcarAttestRequest{
		TEEEvidence: compositeEvidence{
			PrimaryEvidence:    primaryEvidence,
			AdditionalEvidence: "",
		},
		RuntimeData: rd,
	}

	body, err := json.Marshal(attestReq)
	if err != nil {
		return "", fmt.Errorf("marshal attest request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.KBSURL+"/kbs/v0/attest", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "kbs-session-id", Value: sessionID})

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("attest returned %d: %s", resp.StatusCode, respBody)
	}

	var attestResp attestResponse
	if err := json.NewDecoder(resp.Body).Decode(&attestResp); err != nil {
		return "", fmt.Errorf("decode attest response: %w", err)
	}

	return attestResp.Token, nil
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

func (c *Client) signCSR(ctx context.Context, earToken, csrPEM string) (certPEM, caCertPEM []byte, err error) {
	ttl := c.cfg.CertTTL
	if ttl == 0 {
		ttl = ratls.DefaultCertTTL
	}

	body, err := json.Marshal(signCSRRequest{
		EAR: earToken,
		CSR: issuerapi.MustPEMData([]byte(csrPEM)),
		TTL: issuerapi.Duration{Duration: ttl},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal sign-csr request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.IssuerURL+"/v1/sign-csr", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, nil, fmt.Errorf("sign-csr returned %d: %s", resp.StatusCode, respBody)
	}

	var signResp signCSRResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, nil, fmt.Errorf("decode sign-csr response: %w", err)
	}

	return signResp.Certificate.Bytes(), signResp.CACertificate.Bytes(), nil
}

// RefreshCABundle fetches the CA certificate bundle from the cert-issuer's
// /v1/ca endpoint using the cached EAR JWT for authentication. Returns all
// certificates in the bundle (supports multi-PEM for rotation windows).
// If no cached token exists, performs a fresh attestation first.
func (c *Client) RefreshCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	// Ensure we have a valid token. Re-attest if missing or near expiry.
	c.mu.Lock()
	token := c.cachedToken
	c.mu.Unlock()

	if token == "" || tokenExpired(token) {
		var err error
		token, err = c.rcarAttest(ctx)
		if err != nil {
			return nil, fmt.Errorf("attestation for CA bundle: %w", err)
		}
		c.mu.Lock()
		c.cachedToken = token
		c.mu.Unlock()
	}

	certs, err := c.fetchCABundleWithToken(ctx, token)
	if err != nil {
		// Request failed despite token appearing valid; re-attest and retry.
		token, attestErr := c.rcarAttest(ctx)
		if attestErr != nil {
			return nil, fmt.Errorf("re-attestation for CA bundle: %w", attestErr)
		}
		c.mu.Lock()
		c.cachedToken = token
		c.mu.Unlock()

		certs, err = c.fetchCABundleWithToken(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("CA bundle fetch after re-attestation: %w", err)
		}
	}

	return certs, nil
}

// rcarAttest performs the complete RCAR auth → attest flow and returns an EAR token.
// This is the shared core of RequestCert and RefreshCABundle.
func (c *Client) rcarAttest(ctx context.Context) (string, error) {
	challenge, sessionID, err := c.kbsAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("kbs auth: %w", err)
	}

	// The RCAR protocol requires a tee-pubkey JWK in runtime data. In the
	// full KBS key-broker flow, KBS would use this key to JWE-encrypt secrets
	// sent back to the TEE. We only use KBS for attestation (not secret
	// retrieval), so the private key is unused — but KBS validates the
	// field's presence and structure, so we must provide a valid key.
	_, pubKeyJWK, err := generateEphemeralKeypair()
	if err != nil {
		return "", fmt.Errorf("ephemeral keypair: %w", err)
	}

	rd := runtimeData{
		Nonce:     challenge.Nonce,
		TEEPubKey: pubKeyJWK,
	}

	rdJSON, err := json.Marshal(rd)
	if err != nil {
		return "", fmt.Errorf("marshal runtime data: %w", err)
	}
	customData := base64.StdEncoding.EncodeToString(rdJSON)

	evidence, err := c.cfg.AttestFunc(ctx, customData)
	if err != nil {
		return "", fmt.Errorf("attestation: %w", err)
	}

	token, err := c.kbsAttest(ctx, sessionID, evidence, rd)
	if err != nil {
		return "", fmt.Errorf("kbs attest: %w", err)
	}

	return token, nil
}

func (c *Client) fetchCABundleWithToken(ctx context.Context, token string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.IssuerURL+"/v1/ca", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET /v1/ca returned %d: %s", resp.StatusCode, body)
	}

	pemData, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	certs, err := certutil.ParsePEMCertificates(pemData)
	if err != nil {
		return nil, fmt.Errorf("CA bundle: %w", err)
	}

	return certs, nil
}

func (c *Client) fetchCACert(ctx context.Context) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.IssuerURL+"/v1/ca", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET /v1/ca returned %d: %s", resp.StatusCode, body)
	}

	pemData, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, err
	}

	return certutil.ParseCertificatePEM(pemData)
}

// generateEphemeralKeypair creates an ECDSA P-256 keypair and converts the
// public key to JWK format for the RCAR runtime-data.tee-pubkey field.
func generateEphemeralKeypair() (*ecdsa.PrivateKey, teePubKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, teePubKey{}, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// ECDH-ES+A256KW is the correct JWE key encryption algorithm for EC keys.
	pubJWK := teePubKey{
		Kty: "EC",
		Alg: "ECDH-ES+A256KW",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}

	return key, pubJWK, nil
}

// tokenExpiryMargin is how far before the actual exp we consider a token
// expired, avoiding races where the token expires mid-request.
const tokenExpiryMargin = 30 * time.Second

// tokenExpired checks whether a JWT token's exp claim is within the expiry
// margin. Returns true if the token is expired/near-expiry or unparseable.
func tokenExpired(token string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return true
	}
	return time.Until(time.Unix(claims.Exp, 0)) < tokenExpiryMargin
}
