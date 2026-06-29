package getcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestNewCmdFlagDefaultsAndRequired(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "get-cert" {
		t.Fatalf("Use = %q, want get-cert", cmd.Use)
	}

	flags := cmd.Flags()
	for _, name := range []string{"cds-url", "attestation-api-url", "san"} {
		flag := flags.Lookup(name)
		if flag == nil {
			t.Fatalf("flag %q not registered", name)
		}
		if _, ok := flag.Annotations[`cobra_annotation_bash_completion_one_required_flag`]; !ok {
			t.Errorf("flag %q not marked required", name)
		}
	}

	tests := []struct {
		name string
		want string
	}{
		{"key-mode", "0600"},
		{"discovery-public-tls-mode", "cds"},
		{"reload-watch-interval", "1m0s"},
		{"initial-retry-timeout", "2m0s"},
		{"initial-retry-interval", "2s"},
		{"reload-nginx", "true"},
	}
	for _, tt := range tests {
		flag := flags.Lookup(tt.name)
		if flag == nil {
			t.Fatalf("flag %q not registered", tt.name)
		}
		if flag.DefValue != tt.want {
			t.Errorf("flag %q default = %q, want %q", tt.name, flag.DefValue, tt.want)
		}
	}
}

func TestValidateConfigAccepts(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "minimal",
			cfg: config{
				CDSURL:            "http://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "confidential-gke.confidential.ai",
			},
		},
		{
			name: "ip san",
			cfg: config{
				CDSURL:            "https://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "10.0.0.1",
			},
		},
		{
			name: "reload watch with renew",
			cfg: config{
				CDSURL:              "http://cds:8443",
				AttestationApiURL:   "http://attestation-api:8400",
				SAN:                 "host.example.com",
				ReloadWatchPaths:    []string{"/tls.crt"},
				ReloadWatchInterval: time.Minute,
				RenewInterval:       time.Hour,
			},
		},
		{
			name: "continue on initial error with renew",
			cfg: config{
				CDSURL:                 "http://cds:8443",
				AttestationApiURL:      "http://attestation-api:8400",
				SAN:                    "host.example.com",
				ContinueOnInitialError: true,
				RenewInterval:          time.Hour,
			},
		},
		{
			name: "discovery webpki",
			cfg: config{
				CDSURL:                 "http://cds:8443",
				AttestationApiURL:      "http://attestation-api:8400",
				SAN:                    "host.example.com",
				DiscoveryOutPath:       "/tmp/d.json",
				DiscoveryPublicTLSMode: "webpki",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConfig(tt.cfg); err != nil {
				t.Fatalf("validateConfig: %v", err)
			}
		})
	}
}

func TestValidateConfigRejects(t *testing.T) {
	base := config{
		CDSURL:            "http://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	tests := []struct {
		name   string
		mutate func(*config)
	}{
		{"empty cds url", func(c *config) { c.CDSURL = "" }},
		{"bad cds url", func(c *config) { c.CDSURL = "://nope" }},
		{"empty attestation url", func(c *config) { c.AttestationApiURL = "" }},
		{"empty san", func(c *config) { c.SAN = "" }},
		{"url san", func(c *config) { c.SAN = "https://host.example.com" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatal("validateConfig succeeded, want error")
			}
		})
	}
}

func TestValidateSAN(t *testing.T) {
	tests := []struct {
		name    string
		san     string
		wantErr bool
	}{
		{"ipv4", "192.168.1.1", false},
		{"ipv6", "::1", false},
		{"hostname", "host.example.com", false},
		{"single label", "host", false},
		{"empty", "", true},
		{"http url", "http://host", true},
		{"https url", "https://host", true},
		{"wildcard", "*.example.com", true},
		{"trailing dot label", "host..com", true},
		{"too long", strings.Repeat("a", 254), true},
		{"label too long", strings.Repeat("a", 64) + ".com", true},
		{"underscore", "host_name.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSAN(tt.san)
			if tt.wantErr != (err != nil) {
				t.Fatalf("validateSAN(%q) err = %v, wantErr = %v", tt.san, err, tt.wantErr)
			}
		})
	}
}

func TestDiscoveryPublicTLSMode(t *testing.T) {
	if got := discoveryPublicTLSMode(""); got != "cds" {
		t.Fatalf("empty = %q, want cds", got)
	}
	if got := discoveryPublicTLSMode("webpki"); got != "webpki" {
		t.Fatalf("webpki = %q, want webpki", got)
	}
}

func TestValidateOutputPaths(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty paths skipped", func(t *testing.T) {
		if err := validateOutputPaths("", "", ""); err != nil {
			t.Fatalf("validateOutputPaths: %v", err)
		}
	})

	t.Run("writable dir ok", func(t *testing.T) {
		if err := validateOutputPaths(filepath.Join(dir, "cert.pem")); err != nil {
			t.Fatalf("validateOutputPaths: %v", err)
		}
	})

	t.Run("missing dir", func(t *testing.T) {
		if err := validateOutputPaths(filepath.Join(dir, "missing", "cert.pem")); err == nil {
			t.Fatal("validateOutputPaths succeeded, want error for missing dir")
		}
	})

	t.Run("parent is a file", func(t *testing.T) {
		f := filepath.Join(dir, "afile")
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateOutputPaths(filepath.Join(f, "cert.pem")); err == nil {
			t.Fatal("validateOutputPaths succeeded, want error for file parent")
		}
	})
}

func TestLoadOrGenerateKey(t *testing.T) {
	t.Run("generate ephemeral", func(t *testing.T) {
		key, keyPEM, err := loadOrGenerateKey(config{})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if key == nil {
			t.Fatal("nil key")
		}
		if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
			t.Fatalf("keyPEM does not look like a PEM key: %q", keyPEM)
		}
		if key.Curve != elliptic.P256() {
			t.Fatalf("curve = %v, want P-256", key.Curve.Params().Name)
		}
	})

	t.Run("load from disk", func(t *testing.T) {
		dir := t.TempDir()
		genKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		genPEM, err := certutil.MarshalECKeyPEM(genKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(path, genPEM, 0600); err != nil {
			t.Fatal(err)
		}

		key, keyPEM, err := loadOrGenerateKey(config{KeyPath: path})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if !key.Equal(genKey) {
			t.Fatal("loaded key does not match written key")
		}
		if string(keyPEM) != string(genPEM) {
			t.Fatal("returned PEM does not match file contents")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, _, err := loadOrGenerateKey(config{KeyPath: filepath.Join(t.TempDir(), "nope.pem")}); err == nil {
			t.Fatal("loadOrGenerateKey succeeded, want error for missing file")
		}
	})

	t.Run("invalid key contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(path, []byte("not a key"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadOrGenerateKey(config{KeyPath: path}); err == nil {
			t.Fatal("loadOrGenerateKey succeeded, want error for invalid key")
		}
	})
}

func TestCreateCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("dns san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "host.example.com")
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		block, _ := pem.Decode(csrPEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			t.Fatalf("not a CSR PEM: %q", csrPEM)
		}
	})

	t.Run("ip san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "10.0.0.5")
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		if !strings.Contains(string(csrPEM), "CERTIFICATE REQUEST") {
			t.Fatalf("not a CSR PEM: %q", csrPEM)
		}
	})
}

func TestSnapshotReloadWatchPathsErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		if _, err := snapshotReloadWatchPaths([]string{filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("snapshotReloadWatchPaths succeeded, want error for missing file")
		}
	})

	t.Run("directory not allowed", func(t *testing.T) {
		if _, err := snapshotReloadWatchPaths([]string{dir}); err == nil {
			t.Fatal("snapshotReloadWatchPaths succeeded, want error for directory")
		}
	})
}

func TestReloadWatchChangedPropagatesError(t *testing.T) {
	if _, _, err := reloadWatchChanged(nil, []string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("reloadWatchChanged succeeded, want error for missing file")
	}
}

func TestWriteOutputsAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	certPEM := testIssuedChainPEM(t)
	cfg := config{
		SAN:                    "host.example.com",
		OutPath:                filepath.Join(dir, "cert.pem"),
		CAOutPath:              filepath.Join(dir, "ca.pem"),
		KeyOutPath:             filepath.Join(dir, "key.pem"),
		KeyMode:                "0600",
		DiscoveryOutPath:       filepath.Join(dir, "discovery.json"),
		DiscoveryPublicTLSMode: "cds",
	}
	result := attestclient.CertificateResult{
		Certificate: certPEM,
		Challenge:   base64.StdEncoding.EncodeToString([]byte("challenge")),
		Platform:    "snp",
		Evidence:    json.RawMessage(`{"q":"e"}`),
	}

	if err := writeOutputs(cfg, []byte("KEYPEM"), result); err != nil {
		t.Fatalf("writeOutputs: %v", err)
	}

	cert, err := os.ReadFile(cfg.OutPath)
	if err != nil || string(cert) != certPEM {
		t.Fatalf("cert out mismatch: err=%v", err)
	}
	if data, err := os.ReadFile(cfg.KeyOutPath); err != nil || string(data) != "KEYPEM" {
		t.Fatalf("key out mismatch: err=%v", err)
	}
	info, err := os.Stat(cfg.KeyOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode = %#o, want 0600", info.Mode().Perm())
	}
	ca, err := os.ReadFile(cfg.CAOutPath)
	if err != nil || !strings.Contains(string(ca), "CERTIFICATE") {
		t.Fatalf("ca out mismatch: err=%v", err)
	}
	var doc types.DiscoveryDocument
	data, err := os.ReadFile(cfg.DiscoveryOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	if doc.PublicTLS.Hostname != "host.example.com" {
		t.Fatalf("discovery hostname = %q", doc.PublicTLS.Hostname)
	}
}

func TestWriteOutputsBadKeyMode(t *testing.T) {
	err := writeOutputs(config{KeyOutPath: filepath.Join(t.TempDir(), "k"), KeyMode: "abc"}, []byte("k"), attestclient.CertificateResult{})
	if err == nil {
		t.Fatal("writeOutputs succeeded, want error for bad key mode")
	}
}

func TestWriteOutputsCAOutWithoutIssuerFails(t *testing.T) {
	// A chain with only a leaf has no CA bundle to extract.
	leafOnly := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("leaf")}))
	err := writeOutputs(config{CAOutPath: filepath.Join(t.TempDir(), "ca.pem")}, nil, attestclient.CertificateResult{Certificate: leafOnly})
	if err == nil {
		t.Fatal("writeOutputs succeeded, want error extracting CA bundle from leaf-only chain")
	}
}

func TestNewCDSClientInvalidURL(t *testing.T) {
	if _, err := newCDSClient(config{CDSURL: "://bad"}); err == nil {
		t.Fatal("newCDSClient succeeded, want error for invalid URL")
	}
}

func TestSetupLoggingDoesNotPanic(t *testing.T) {
	setupLogging(true)
	setupLogging(false)
}

// fakeCDSAndAttestation wires up an httptest server playing both the CDS role
// (/authenticate, /attest) and a separate attestation-api server (/attest).
// The challenge is valid base64 and the attestation-api echoes evidence so the
// full obtainCert flow can run without real TEE hardware.
func startFakeServers(t *testing.T, issuedChain string) (cdsURL, attURL string) {
	t.Helper()

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": json.RawMessage(`{"quote":"fake"}`),
		})
	}))
	t.Cleanup(att.Close)

	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("the-challenge")),
			})
		case "/attest":
			_, _ = w.Write([]byte(issuedChain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	return cds.URL, att.URL
}

func TestObtainCertEndToEnd(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
	}
	client, err := newCDSClient(cfg)
	if err != nil {
		t.Fatalf("newCDSClient: %v", err)
	}
	if err := obtainCert(context.Background(), cfg, client); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}
	got, err := os.ReadFile(cfg.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != chain {
		t.Fatalf("written cert does not match issued chain")
	}
}

func TestObtainCertCDSError(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": json.RawMessage(`{}`)})
	}))
	t.Cleanup(att.Close)
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(cds.Close)

	cfg := config{CDSURL: cds.URL, AttestationApiURL: att.URL, SAN: "host.example.com"}
	client, err := newCDSClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := obtainCert(context.Background(), cfg, client); err == nil {
		t.Fatal("obtainCert succeeded, want error when CDS fails")
	}
}

func TestObtainCertWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": json.RawMessage(`{}`)})
	}))
	t.Cleanup(att.Close)

	var calls int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			calls++
			if calls == 1 {
				http.Error(w, "warming up", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("c")),
			})
		case "/attest":
			_, _ = w.Write([]byte(chain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	cfg := config{
		CDSURL:               cds.URL,
		AttestationApiURL:    att.URL,
		SAN:                  "host.example.com",
		OutPath:              filepath.Join(dir, "cert.pem"),
		InitialRetryTimeout:  5 * time.Second,
		InitialRetryInterval: time.Millisecond,
	}
	client, err := newCDSClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := obtainCertWithRetry(context.Background(), cfg, client); err != nil {
		t.Fatalf("obtainCertWithRetry: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected a retry, got %d calls", calls)
	}
}

func TestObtainCertWithRetryNoTimeoutTriesOnce(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": json.RawMessage(`{}`)})
	}))
	t.Cleanup(att.Close)
	var calls int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(cds.Close)

	cfg := config{CDSURL: cds.URL, AttestationApiURL: att.URL, SAN: "host.example.com", InitialRetryTimeout: 0}
	client, err := newCDSClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := obtainCertWithRetry(context.Background(), cfg, client); err == nil {
		t.Fatal("obtainCertWithRetry succeeded, want error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want exactly 1 with no retry timeout", calls)
	}
}

func TestRunOnceWritesCert(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
		// run-once mode: RenewInterval == 0
	}
	if err := run(cfg); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(cfg.OutPath); err != nil {
		t.Fatalf("cert not written: %v", err)
	}
}

func TestRunValidationError(t *testing.T) {
	if err := run(config{CDSURL: "", AttestationApiURL: "http://a", SAN: "h"}); err == nil {
		t.Fatal("run succeeded, want validation error")
	}
}

// testIssuedChainPEM builds a two-cert PEM chain (leaf + one issuer) that parses
// as real certificates, so buildDiscoveryDocument and caBundleFromChain succeed.
func testIssuedChainPEM(t *testing.T) string {
	t.Helper()
	leaf := testCertificatePEM(t)
	ca := testCertificatePEM(t)
	return leaf + ca
}
