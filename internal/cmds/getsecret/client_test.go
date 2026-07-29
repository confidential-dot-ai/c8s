package getsecret

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeLeaf stages a certificate and key where the cert sidecar would leave
// them.
func writeLeaf(t *testing.T, dir string) (certPath, keyPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	write(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath, &key.PublicKey
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The sandbox token binds to the leaf's key, so newClient must return the key
// of the certificate it presents — not a fresh one.
func TestNewClientReturnsLeafKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, want := writeLeaf(t, dir)
	cfg := validConfig(t)
	cfg.CertPath, cfg.KeyPath = certPath, keyPath

	client, pub, err := newClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("no client returned")
	}
	got, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	if !got.Equal(want) {
		t.Fatal("returned key is not the leaf's")
	}
}

// A missing or unreadable leaf is a retryable failure, not a panic: the cert
// sidecar may not have written it yet.
func TestNewClientWithoutLeaf(t *testing.T) {
	for _, tc := range []struct{ name, cert, key string }{
		{"absent", "nope.crt", "nope.key"},
		{"garbage", "bad.crt", "bad.key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := validConfig(t)
			cfg.CertPath = filepath.Join(dir, tc.cert)
			cfg.KeyPath = filepath.Join(dir, tc.key)
			if tc.name == "garbage" {
				write(t, cfg.CertPath, []byte("not a pem"))
				write(t, cfg.KeyPath, []byte("not a pem"))
			}
			if _, _, err := newClient(cfg, nil); err == nil {
				t.Fatal("a missing leaf was accepted")
			}
		})
	}
}

// The provider reloads from disk, so a renewal written by the cert sidecar is
// picked up without restarting this one.
func TestLeafProviderReloads(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, first := writeLeaf(t, dir)
	p := leafProvider{certPath: certPath, keyPath: keyPath}

	got, ttl, err := p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Fatalf("ttl = %v, want positive", ttl)
	}
	parsed, _ := x509.ParseCertificate(got.Certificate[0])
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(first) {
		t.Fatal("first provision returned the wrong key")
	}

	_, _, second := writeLeaf(t, dir) // renewal lands on the same paths
	got, _, err = p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = x509.ParseCertificate(got.Certificate[0])
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(second) {
		t.Fatal("provision did not pick up the renewed leaf")
	}
}

func TestFetchChallengeFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"server refuses", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusServiceUnavailable)
		}},
		{"not json", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("not json"))
		}},
		{"not base64", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"challenge":"!!!"}`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			cfg := flowConfig(t, srv.URL)
			if _, err := fetchChallenge(context.Background(), cfg, http.DefaultClient); err == nil {
				t.Fatal("a bad challenge response was accepted")
			}
		})
	}
}

// An unreachable CDS is an error, not a hang or a nil value.
func TestFetchChallengeUnreachable(t *testing.T) {
	cfg := flowConfig(t, "http://127.0.0.1:1")
	cfg.RequestTimeout = 200 * time.Millisecond
	if _, err := fetchChallenge(context.Background(), cfg, http.DefaultClient); err == nil {
		t.Fatal("an unreachable CDS reported success")
	}
}

// A malformed success body must not be mistaken for a secret.
func TestSecretResponseMustBeDecodable(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"value not base64", `{"value":"!!!"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startInventory(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/secrets" {
					w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
					return
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cfg := flowConfig(t, srv.URL)
			_, _, err := do(context.Background(), cfg, http.DefaultClient, testKey(t), http.MethodGet, "/api/db")
			if err == nil {
				t.Fatal("an undecodable body was accepted as a secret")
			}
		})
	}
}

// The inventory is where the sandbox token comes from; without it there is no
// request to make.
func TestUnreachableInventoryFails(t *testing.T) {
	prev := inventoryEndpoint
	inventoryEndpoint = func() string { return "unix://" + filepath.Join(t.TempDir(), "absent.sock") }
	t.Cleanup(func() { inventoryEndpoint = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	}))
	defer srv.Close()
	cfg := flowConfig(t, srv.URL)
	_, _, err := do(context.Background(), cfg, http.DefaultClient, testKey(t), http.MethodGet, "/api/db")
	if err == nil || !strings.Contains(err.Error(), "sandbox token") {
		t.Fatalf("err = %v, want a sandbox-token failure", err)
	}
}

// An unwritable output directory fails loudly rather than reporting success
// with no file on disk.
func TestWriteAllUnwritable(t *testing.T) {
	cfg := validConfig(t)
	cfg.OutDir = filepath.Join(cfg.OutDir, "readonly", "secrets")
	if err := os.MkdirAll(filepath.Dir(cfg.OutDir), 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the directory mode")
	}
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("v")}); err == nil {
		t.Fatal("an unwritable directory reported success")
	}
}

func TestWriteAllRejectsBadMode(t *testing.T) {
	cfg := validConfig(t)
	cfg.FileMode = "notamode"
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("v")}); err == nil {
		t.Fatal("a bad file mode was accepted")
	}
}
