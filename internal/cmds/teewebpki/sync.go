package teewebpki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	statepkg "github.com/confidential-dot-ai/c8s/internal/teewebpki"
)

type syncer struct {
	cfg    config
	client *http.Client
	reload func() error

	mu                    sync.RWMutex
	ready                 bool
	lastLoadedCertificate []byte
}

func (s *syncer) sync(ctx context.Context) (bool, error) {
	state, err := s.getState(ctx)
	if err != nil {
		return false, err
	}
	key, err := statepkg.PrivateKey(state.TLSKeySeed)
	if err != nil {
		return false, err
	}
	if err := writePrivateKey(s.cfg.OutKey, key); err != nil {
		return false, fmt.Errorf("write protected TLS key: %w", err)
	}

	csrPEM, err := makeCSR(key, s.cfg.DNSNames)
	if err != nil {
		return false, err
	}
	if err := fileutil.WriteAtomic(s.cfg.OutCSR, csrPEM, 0o644); err != nil {
		return false, fmt.Errorf("write public CSR: %w", err)
	}
	if !bytes.Equal(csrPublicKey(state.CSRPEM), csrPublicKey(csrPEM)) || !csrNamesEqual(state.CSRPEM, s.cfg.DNSNames) {
		if err := s.putState(ctx, statepkg.PublicUpdate{Version: state.Version, CSRPEM: csrPEM}); err != nil {
			return false, err
		}
		state, err = s.getState(ctx)
		if err != nil {
			return false, err
		}
	}

	if len(state.CertificatePEM) == 0 {
		// Do not create a temporary certificate. Without a public chain, nginx
		// cannot bind its serving socket successfully.
		_ = os.Remove(s.cfg.OutCert)
		return false, nil
	}
	if err := s.verifyPublicCertificate(state.CertificatePEM, key); err != nil {
		return false, err
	}
	if err := fileutil.WriteAtomic(s.cfg.OutCert, state.CertificatePEM, 0o644); err != nil {
		return false, fmt.Errorf("write public certificate: %w", err)
	}
	if s.cfg.ReloadNginx && !bytes.Equal(s.lastLoadedCertificate, state.CertificatePEM) {
		if s.reload == nil {
			return false, fmt.Errorf("reload nginx: reload function is not configured")
		}
		if err := s.reload(); err != nil {
			return false, fmt.Errorf("reload nginx: %w", err)
		}
		s.lastLoadedCertificate = append(s.lastLoadedCertificate[:0], state.CertificatePEM...)
	}
	return true, nil
}

func (s *syncer) getState(ctx context.Context) (statepkg.Snapshot, error) {
	var state statepkg.Snapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.CDSURL+statepkg.Route, nil)
	if err != nil {
		return state, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return state, fmt.Errorf("get protected TLS state: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return state, fmt.Errorf("get protected TLS state: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, statepkg.MaxRequestBytes)).Decode(&state); err != nil {
		return state, err
	}
	if err := statepkg.ValidateSnapshot(state); err != nil {
		return state, err
	}
	return state, nil
}

func (s *syncer) putState(ctx context.Context, update statepkg.PublicUpdate) error {
	body, err := marshalJSON(update)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.cfg.CDSURL+statepkg.Route, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("update public TLS state: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("update public TLS state: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}

func (s *syncer) verifyPublicCertificate(chainPEM []byte, key *ecdsa.PrivateKey) error {
	leaf, intermediates, err := parseCertificateChain(chainPEM)
	if err != nil {
		return err
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(&key.PublicKey) {
		return fmt.Errorf("public certificate does not match the protected TLS key")
	}
	roots, err := loadRoots(s.cfg.PublicRoots)
	if err != nil {
		return fmt.Errorf("load public roots: %w", err)
	}
	pool := x509.NewCertPool()
	for _, cert := range intermediates {
		pool.AddCert(cert)
	}
	for _, name := range s.cfg.DNSNames {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: pool}); err != nil {
			return fmt.Errorf("verify public certificate for %s: %w", name, err)
		}
	}
	return nil
}

func makeCSR(key *ecdsa.PrivateKey, dnsNames []string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsNames[0]},
		DNSNames: append([]string(nil), dnsNames...),
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create public certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func csrPublicKey(csrPEM []byte) []byte {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil
	}
	der, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	return der
}

func csrNamesEqual(csrPEM []byte, names []string) bool {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return false
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || len(csr.DNSNames) != len(names) {
		return false
	}
	for i := range names {
		if csr.DNSNames[i] != names[i] {
			return false
		}
	}
	return true
}

func (s *syncer) setReady(ready bool) {
	s.mu.Lock()
	s.ready = ready
	s.mu.Unlock()
}

func (s *syncer) serveReady(ctx context.Context) {
	if s.cfg.ReadyAddress == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.RLock()
		ready := s.ready
		s.mu.RUnlock()
		if !ready {
			http.Error(w, "public certificate is not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Addr: s.cfg.ReadyAddress, Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "tee-webpki readiness server failed: %v\n", err)
	}
}
