package kbsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockKBSServer creates a test HTTP server that simulates the KBS RCAR
// auth/attest flow and the cert-issuer sign-csr endpoint.
func mockKBSServer(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, tokenKey *ecdsa.PrivateKey) (*httptest.Server, *httptest.Server) {
	t.Helper()

	// KBS server (auth + attest) — validates RCAR protocol fields.
	kbs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kbs/v0/auth":
			// Validate RCAR auth request format.
			var req authRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			if req.Version == "" {
				http.Error(w, `{"detail":"missing field version"}`, 401)
				return
			}
			if req.TEE == "" {
				http.Error(w, `{"detail":"missing field tee"}`, 401)
				return
			}
			// Set session cookie like real KBS.
			http.SetCookie(w, &http.Cookie{
				Name:  "kbs-session-id",
				Value: "test-session-42",
			})
			json.NewEncoder(w).Encode(challengeResponse{Nonce: "test-nonce-abc"})

		case "/kbs/v0/attest":
			// Validate session cookie.
			cookie, err := r.Cookie("kbs-session-id")
			if err != nil || cookie.Value == "" {
				http.Error(w, "missing session cookie", 401)
				return
			}
			// Validate attest request has runtime-data.
			var req rcarAttestRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			if req.RuntimeData.Nonce == "" {
				http.Error(w, "missing runtime-data nonce", 400)
				return
			}
			// Create a mock EAR token (ES256 JWT signed by tokenKey).
			token := createMockEAR(t, tokenKey)
			json.NewEncoder(w).Encode(attestResponse{Token: token})
		default:
			http.NotFound(w, r)
		}
	}))

	// Cert-issuer server.
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sign-csr":
			var req signCSRRequest
			json.NewDecoder(r.Body).Decode(&req)

			// CSR is already PEM-validated by issuerapi.PEMData unmarshal.
			if req.CSR.DER() == nil {
				http.Error(w, "bad CSR", 400)
				return
			}
			csr, err := x509.ParseCertificateRequest(req.CSR.DER())
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}

			// Sign the cert.
			serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      csr.Subject,
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(1 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				IPAddresses:  csr.IPAddresses,
				DNSNames:     csr.DNSNames,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}

			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
			caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

			json.NewEncoder(w).Encode(signCSRResponse{
				Certificate:   issuerapi.MustPEMData(certPEM),
				CACertificate: issuerapi.MustPEMData(caCertPEM),
			})

		case "/v1/ca":
			w.Header().Set("Content-Type", "application/x-pem-file")
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

		default:
			http.NotFound(w, r)
		}
	}))

	return kbs, issuer
}

func createMockEAR(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":     "kbs",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
		"submods": "mock-evidence",
	})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := header + "." + payload

	h := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])

	keySize := 32
	sig := make([]byte, 2*keySize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Mesh CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func TestProviderProvision(t *testing.T) {
	caKey, caCert := testCA(t)
	tokenKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kbs, issuer := mockKBSServer(t, caKey, caCert, tokenKey)
	defer kbs.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		KBSURL:    kbs.URL,
		IssuerURL: issuer.URL,
		TEEType:   "az-snp-vtpm",
		AttestFunc: func(_ context.Context, _ string) (string, error) {
			return "mock-evidence", nil
		},
		CertTTL:  1 * time.Hour,
		NodeIP:   "10.0.0.1",
		NodeName: "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cert, ttl, err := p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cert == nil {
		t.Fatal("cert is nil")
	}
	if cert.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if cert.Leaf == nil {
		t.Fatal("leaf cert is nil")
	}
	if len(cert.Certificate) < 2 {
		t.Fatalf("expected cert chain with leaf + CA, got %d certs", len(cert.Certificate))
	}
	if ttl <= 0 {
		t.Fatalf("TTL = %v, expected positive", ttl)
	}

	// Verify the cert chains to the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("cert doesn't chain to CA: %v", err)
	}

	// Check subject.
	if cn := cert.Leaf.Subject.CommonName; cn != "ratls-mesh-10.0.0.1" {
		t.Errorf("CN = %q, want %q", cn, "ratls-mesh-10.0.0.1")
	}
}

func TestProviderCACert(t *testing.T) {
	caKey, caCert := testCA(t)
	tokenKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, issuer := mockKBSServer(t, caKey, caCert, tokenKey)
	defer issuer.Close()

	p, err := NewProvider(&Config{
		KBSURL:    "http://unused",
		IssuerURL: issuer.URL,
		TEEType:   "az-snp-vtpm",
		AttestFunc: func(_ context.Context, _ string) (string, error) {
			return "", nil
		},
		NodeIP: "10.0.0.1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := p.CACert(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject.CommonName != "Test Mesh CA" {
		t.Errorf("CA CN = %q, want %q", got.Subject.CommonName, "Test Mesh CA")
	}
}

func TestNewProviderValidation(t *testing.T) {
	base := Config{
		KBSURL:     "http://kbs",
		IssuerURL:  "http://issuer",
		TEEType:    "az-snp-vtpm",
		AttestFunc: func(context.Context, string) (string, error) { return "", nil },
		NodeIP:     "10.0.0.1",
	}

	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"missing KBSURL", func(c *Config) { c.KBSURL = "" }},
		{"missing IssuerURL", func(c *Config) { c.IssuerURL = "" }},
		{"missing TEEType", func(c *Config) { c.TEEType = "" }},
		{"missing AttestFunc", func(c *Config) { c.AttestFunc = nil }},
		{"missing NodeIP", func(c *Config) { c.NodeIP = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.modify(&cfg)
			_, err := NewProvider(&cfg, nil)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestTokenExpired(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		expired bool
	}{
		{"empty", "", true},
		{"malformed", "not-a-jwt", true},
		{"no exp", makeJWT(map[string]any{"iss": "kbs"}), true},
		{"expired", makeJWT(map[string]any{"exp": time.Now().Add(-1 * time.Minute).Unix()}), true},
		{"within margin", makeJWT(map[string]any{"exp": time.Now().Add(10 * time.Second).Unix()}), true},
		{"valid", makeJWT(map[string]any{"exp": time.Now().Add(5 * time.Minute).Unix()}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tokenExpired(tt.token); got != tt.expired {
				t.Errorf("tokenExpired() = %v, want %v", got, tt.expired)
			}
		})
	}
}
