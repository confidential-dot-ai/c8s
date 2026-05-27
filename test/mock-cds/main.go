// mock-cds is a fake CDS attestation+signing service for integration testing.
// It implements /authenticate and /attest endpoints but skips real TEE verification.
// On /attest it signs the provided CSR with an ephemeral CA, returning a valid certificate.
// Use only in test environments.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	caKey  ecdsa.PrivateKey
	caCert x509.Certificate
	caDER  []byte
)

func init() {
	// Generate an ephemeral CA at startup.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate CA key: %v", err))
	}
	caKey = *key

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-cds-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("failed to create CA cert: %v", err))
	}
	caDER = der

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("failed to parse CA cert: %v", err))
	}
	caCert = *parsed
}

type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]time.Time
}

func newChallengeStore() challengeStore {
	return challengeStore{challenges: make(map[string]time.Time)}
}

func (s *challengeStore) issue() string {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	encoded := base64.StdEncoding.EncodeToString(nonce)
	s.mu.Lock()
	s.challenges[encoded] = time.Now().Add(5 * time.Minute)
	s.mu.Unlock()
	return encoded
}

func (s *challengeStore) consume(challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.challenges[challenge]
	if !ok || time.Now().After(exp) {
		return false
	}
	delete(s.challenges, challenge)
	return true
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	store := newChallengeStore()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", func(w http.ResponseWriter, r *http.Request) {
		challenge := store.issue()
		slog.Info("issued challenge")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"challenge": challenge})
	})
	mux.HandleFunc("POST /attest", handleAttest(&store))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	slog.Info("mock cds starting", "port", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func handleAttest(store *challengeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Challenge string          `json:"challenge"`
			Evidence  json.RawMessage `json:"evidence"`
			CSR       string          `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %s", err), http.StatusBadRequest)
			return
		}

		if !store.consume(req.Challenge) {
			http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
			return
		}

		// Parse the CSR.
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			http.Error(w, "invalid CSR: no PEM block", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid CSR: %s", err), http.StatusBadRequest)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			http.Error(w, fmt.Sprintf("CSR signature invalid: %s", err), http.StatusBadRequest)
			return
		}

		// Sign the certificate with the mock CA.
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-1 * time.Minute),
			NotAfter:     time.Now().Add(30 * 24 * time.Hour), // 30 days
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     csr.DNSNames,
			IPAddresses:  csr.IPAddresses,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &caCert, csr.PublicKey, &caKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to sign certificate: %s", err), http.StatusInternalServerError)
			return
		}

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		slog.Info("issued certificate",
			"dns_names", csr.DNSNames,
			"ip_addresses", csr.IPAddresses,
			"serial", serial.String(),
		)

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(certPEM)
	}
}
