package getcert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/snpvcek"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// snpFixturePath is real bare-metal SNP evidence (shared with localverify's
// tests) whose report a KDS-stubbed embedder can pair with its true VCEK.
const snpFixturePath = "../../localverify/testdata/snp-evidence-genoa.json"

func loadSnpFixture(t *testing.T) (chainless json.RawMessage, vcekDER []byte) {
	t.Helper()
	raw, err := os.ReadFile(snpFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Evidence struct {
			AttestationReport string `json:"attestation_report"`
			CertChain         struct {
				Vcek string `json:"vcek"`
			} `json:"cert_chain"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	vcekDER, err = base64.StdEncoding.DecodeString(envelope.Evidence.CertChain.Vcek)
	if err != nil {
		t.Fatal(err)
	}
	chainless, err = json.Marshal(map[string]any{
		"attestation_report": envelope.Evidence.AttestationReport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return chainless, vcekDER
}

// stubVCEKEmbedder swaps the package embedder for one whose KDS fetch is
// canned, and restores it on cleanup.
func stubVCEKEmbedder(t *testing.T, body []byte, err error) {
	t.Helper()
	old := vcekEmbedder
	vcekEmbedder = snpvcek.NewWithGetter(cannedGetter{body: body, err: err})
	t.Cleanup(func() { vcekEmbedder = old })
}

type cannedGetter struct {
	body []byte
	err  error
}

func (g cannedGetter) Get(string) ([]byte, error) { return g.body, g.err }

// startFakeServersWithEvidence is startFakeServers with the attestation-api
// serving the given snp evidence.
func startFakeServersWithEvidence(t *testing.T, issuedChain string, evidence json.RawMessage) (cdsURL, attURL string) {
	t.Helper()

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": evidence})
	}))
	t.Cleanup(att.Close)

	var mu sync.Mutex
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
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

func discoveryEvidence(t *testing.T, path string) (types.DiscoveryDocument, struct {
	AttestationReport string `json:"attestation_report"`
	CertChain         *struct {
		Vcek string `json:"vcek"`
	} `json:"cert_chain"`
}) {
	t.Helper()
	var doc types.DiscoveryDocument
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	var ev struct {
		AttestationReport string `json:"attestation_report"`
		CertChain         *struct {
			Vcek string `json:"vcek"`
		} `json:"cert_chain"`
	}
	if err := json.Unmarshal(doc.Attestation.Evidence, &ev); err != nil {
		t.Fatalf("discovery evidence: %v", err)
	}
	return doc, ev
}

func TestObtainCertEmbedsVCEKInDiscoveryEvidence(t *testing.T) {
	chainless, vcekDER := loadSnpFixture(t)
	stubVCEKEmbedder(t, vcekDER, nil)

	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServersWithEvidence(t, chain, chainless)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
		DiscoveryOutPath:  filepath.Join(dir, "discovery.json"),
	}
	if _, err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL)); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}

	_, ev := discoveryEvidence(t, cfg.DiscoveryOutPath)
	if ev.CertChain == nil || ev.CertChain.Vcek != base64.StdEncoding.EncodeToString(vcekDER) {
		t.Fatalf("discovery evidence cert_chain = %+v, want the embedded VCEK", ev.CertChain)
	}
}

func TestObtainCertWritesDiscoveryWhenKDSUnreachable(t *testing.T) {
	chainless, _ := loadSnpFixture(t)
	stubVCEKEmbedder(t, nil, errors.New("kds unreachable"))

	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServersWithEvidence(t, chain, chainless)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
		DiscoveryOutPath:  filepath.Join(dir, "discovery.json"),
	}
	c := captureDefaultLogger(t)
	if _, err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL)); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}

	_, ev := discoveryEvidence(t, cfg.DiscoveryOutPath)
	if ev.CertChain != nil {
		t.Fatalf("cert_chain = %+v, want none when KDS is unreachable", ev.CertChain)
	}
	if _, ok := c.find("discovery evidence carries no inline VCEK; offline verifiers (c8s-verify-js) will reject it until a renewal embeds one"); !ok {
		t.Fatal("no warning logged for chainless discovery evidence")
	}
}
