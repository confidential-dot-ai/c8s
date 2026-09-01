package teewebpki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	statepkg "github.com/confidential-dot-ai/c8s/internal/teewebpki"
)

func TestReplicasLoadSameKeyAndRenewCertificate(t *testing.T) {
	store, err := statepkg.NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(statepkg.Route, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(store.Snapshot())
		case http.MethodPut:
			var update statepkg.PublicUpdate
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, err := store.UpdatePublicState(update); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	rootCert, rootKey, rootPEM := testRoot(t)
	rootFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootFile, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	reloadCount := 0
	newSyncer := func(dir string) *syncer {
		return &syncer{cfg: config{
			CDSURL: server.URL, DNSNames: []string{"api.example"},
			OutCert: filepath.Join(dir, "tls.crt"), OutKey: filepath.Join(dir, "tls.key"),
			OutCSR: filepath.Join(dir, "tls.csr"), PublicRoots: rootFile, ReloadNginx: true,
		}, client: server.Client(), reload: func() error {
			reloadCount++
			return nil
		}}
	}

	firstDir, secondDir := t.TempDir(), t.TempDir()
	first, second := newSyncer(firstDir), newSyncer(secondDir)
	if ready, err := first.sync(context.Background()); err != nil || ready {
		t.Fatalf("first sync = ready %t, err %v; want a pending CSR", ready, err)
	}
	if _, err := os.Stat(filepath.Join(firstDir, "tls.crt")); !os.IsNotExist(err) {
		t.Fatalf("helper created a certificate before public issuance: %v", err)
	}
	keyA, err := os.ReadFile(filepath.Join(firstDir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := second.sync(context.Background()); err != nil || ready {
		t.Fatalf("second sync = ready %t, err %v; want a pending CSR", ready, err)
	}
	keyB, err := os.ReadFile(filepath.Join(secondDir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(keyA) != string(keyB) {
		t.Fatal("TLS-LB replicas derived different cluster keys")
	}

	state := store.Snapshot()
	key, err := statepkg.PrivateKey(state.TLSKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	chain := testLeaf(t, key, rootCert, rootKey, "api.example")
	if _, err := store.UpdatePublicState(statepkg.PublicUpdate{
		Version: state.Version, CertificatePEM: chain,
	}); err != nil {
		t.Fatal(err)
	}
	if ready, err := first.sync(context.Background()); err != nil || !ready {
		t.Fatalf("certificate sync = ready %t, err %v", ready, err)
	}
	if reloadCount != 1 {
		t.Fatalf("certificate install sent %d reloads, want 1", reloadCount)
	}
	if got, err := os.ReadFile(filepath.Join(firstDir, "tls.crt")); err != nil || string(got) != string(chain) {
		t.Fatalf("installed certificate mismatch: %v", err)
	}

	// A restarted replica gets the same key and current public chain from CDS.
	restartedDir := t.TempDir()
	restarted := newSyncer(restartedDir)
	if ready, err := restarted.sync(context.Background()); err != nil || !ready {
		t.Fatalf("restart sync = ready %t, err %v", ready, err)
	}
	if reloadCount != 2 {
		t.Fatalf("restarted sidecar sent %d total reloads, want 2", reloadCount)
	}
	restartedKey, err := os.ReadFile(filepath.Join(restartedDir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restartedKey, keyA) {
		t.Fatal("restarted replica derived a different cluster key")
	}

	// Certificate renewal changes only public state. The protected key stays
	// stable across the renewal.
	renewed := testLeaf(t, key, rootCert, rootKey, "api.example")
	if bytes.Equal(renewed, chain) {
		t.Fatal("test renewal produced the same certificate bytes")
	}
	state = store.Snapshot()
	if _, err := store.UpdatePublicState(statepkg.PublicUpdate{
		Version: state.Version, CertificatePEM: renewed,
	}); err != nil {
		t.Fatal(err)
	}
	if ready, err := restarted.sync(context.Background()); err != nil || !ready {
		t.Fatalf("renewal sync = ready %t, err %v", ready, err)
	}
	if reloadCount != 3 {
		t.Fatalf("certificate renewal sent %d total reloads, want 3", reloadCount)
	}
	gotRenewed, err := os.ReadFile(filepath.Join(restartedDir, "tls.crt"))
	if err != nil || !bytes.Equal(gotRenewed, renewed) {
		t.Fatalf("renewed certificate mismatch: %v", err)
	}
	keyAfterRenewal, err := os.ReadFile(filepath.Join(restartedDir, "tls.key"))
	if err != nil || !bytes.Equal(keyAfterRenewal, keyA) {
		t.Fatalf("renewal changed the protected key: %v", err)
	}
	if ready, err := restarted.sync(context.Background()); err != nil || !ready {
		t.Fatalf("unchanged sync = ready %t, err %v", ready, err)
	}
	if reloadCount != 3 {
		t.Fatalf("unchanged certificate caused a reload: total = %d, want 3", reloadCount)
	}

	// A failed reload withholds readiness and is retried. The sidecar does not
	// mark certificate bytes as loaded until nginx accepts the signal.
	failCount := 0
	failingDir := t.TempDir()
	failing := &syncer{cfg: config{
		CDSURL: server.URL, DNSNames: []string{"api.example"},
		OutCert: filepath.Join(failingDir, "tls.crt"), OutKey: filepath.Join(failingDir, "tls.key"),
		OutCSR: filepath.Join(failingDir, "tls.csr"), PublicRoots: rootFile, ReloadNginx: true,
	}, client: server.Client(), reload: func() error {
		failCount++
		if failCount == 1 {
			return errors.New("nginx is not running")
		}
		return nil
	}}
	if ready, err := failing.sync(context.Background()); err == nil || ready {
		t.Fatalf("failed reload = ready %t, err %v; want not ready", ready, err)
	}
	if ready, err := failing.sync(context.Background()); err != nil || !ready {
		t.Fatalf("reload retry = ready %t, err %v", ready, err)
	}
	if failCount != 2 {
		t.Fatalf("reload attempts = %d, want 2", failCount)
	}
}

func TestInitWaitsFailClosedForPublicCertificate(t *testing.T) {
	store, err := statepkg.NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, rootKey, rootPEM := testRoot(t)
	rootFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootFile, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := statepkg.PrivateKey(store.Snapshot().TLSKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	chain := testLeaf(t, key, rootCert, rootKey, "api.example")

	var getCount int
	mux := http.NewServeMux()
	mux.HandleFunc(statepkg.Route, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getCount++
			// The first loop publishes the CSR. The second loop sees the public
			// certificate. Until then, no certificate file can exist.
			if getCount == 3 {
				state := store.Snapshot()
				if _, err := store.UpdatePublicState(statepkg.PublicUpdate{
					Version: state.Version, CertificatePEM: chain,
				}); err != nil {
					t.Errorf("issue test certificate: %v", err)
				}
			}
			_ = json.NewEncoder(w).Encode(store.Snapshot())
		case http.MethodPut:
			var update statepkg.PublicUpdate
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, err := store.UpdatePublicState(update); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	outDir := t.TempDir()
	s := &syncer{cfg: config{
		CDSURL: server.URL, DNSNames: []string{"api.example"},
		OutCert: filepath.Join(outDir, "tls.crt"), OutKey: filepath.Join(outDir, "tls.key"),
		OutCSR: filepath.Join(outDir, "tls.csr"), PublicRoots: rootFile,
		PollInterval: 5 * time.Millisecond,
	}, client: server.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.waitForCertificate(ctx); err != nil {
		t.Fatalf("wait for certificate: %v", err)
	}
	got, err := os.ReadFile(s.cfg.OutCert)
	if err != nil || !bytes.Equal(got, chain) {
		t.Fatalf("init did not install the issued public chain: %v", err)
	}
}

func TestInitTimeoutLeavesNoCertificate(t *testing.T) {
	store, err := statepkg.NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(statepkg.Route, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(store.Snapshot())
			return
		}
		var update statepkg.PublicUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := store.UpdatePublicState(update); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	outDir := t.TempDir()
	s := &syncer{cfg: config{
		CDSURL: server.URL, DNSNames: []string{"api.example"},
		OutCert: filepath.Join(outDir, "tls.crt"), OutKey: filepath.Join(outDir, "tls.key"),
		OutCSR: filepath.Join(outDir, "tls.csr"), PollInterval: time.Millisecond,
	}, client: server.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.waitForCertificate(ctx); err == nil {
		t.Fatal("init succeeded without a public certificate")
	}
	if _, err := os.Stat(s.cfg.OutCert); !os.IsNotExist(err) {
		t.Fatalf("init left a certificate before public issuance: %v", err)
	}
}

func testRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testLeaf(t *testing.T, key *ecdsa.PrivateKey, root *x509.Certificate, rootKey *ecdsa.PrivateKey, name string) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
}
