package cdsattest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/snpvcek"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFixtureEvidenceBareObject(t *testing.T) {
	raw := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`
	path := writeTempFile(t, "bare.json", raw)
	p, err := LoadFixtureEvidence(path, "snp", "genoa")
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Raw) != raw || p.Platform != "snp" || p.Generation != "genoa" {
		t.Fatalf("unexpected provider: %+v", p)
	}
	ev, platform, generation, err := p.Evidence(context.Background(), []byte("ignored"))
	if err != nil || string(ev) != raw || platform != "snp" || generation != "genoa" {
		t.Fatalf("Evidence() = %q, %q, %q, %v", ev, platform, generation, err)
	}
}

func TestLoadFixtureEvidenceEnvelope(t *testing.T) {
	inner := `{"attestation_report":"AAAA"}`
	path := writeTempFile(t, "env.json", `{"platform":"tdx","evidence":`+inner+`}`)

	// Empty platform argument takes the envelope's platform.
	p, err := LoadFixtureEvidence(path, "", "genoa")
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Raw) != inner || p.Platform != "tdx" {
		t.Fatalf("unexpected provider: %+v", p)
	}

	// An explicit platform argument wins over the envelope.
	p, err = LoadFixtureEvidence(path, "snp", "genoa")
	if err != nil {
		t.Fatal(err)
	}
	if p.Platform != "snp" {
		t.Fatalf("platform = %q, want snp", p.Platform)
	}
}

func TestLoadFixtureEvidenceDefaultsPlatform(t *testing.T) {
	// Non-envelope content with no platform argument defaults to snp.
	path := writeTempFile(t, "list.json", `["not","an","envelope"]`)
	p, err := LoadFixtureEvidence(path, "", "milan")
	if err != nil {
		t.Fatal(err)
	}
	if p.Platform != "snp" {
		t.Fatalf("platform = %q, want snp default", p.Platform)
	}
}

func TestLiveEvidenceProvider(t *testing.T) {
	var gotReq types.AttestRequest
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/attest" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(types.AttestResponse{
			Platform: "snp",
			Evidence: json.RawMessage(`{"attestation_report":"AAAA"}`),
		})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{
		Client:     attestationclient.NewClient(api.URL),
		Platform:   types.PlatformSnp,
		Generation: "genoa",
	}
	ev, platform, generation, err := p.Evidence(context.Background(), []byte("report-data"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ev) != `{"attestation_report":"AAAA"}` || platform != "snp" || generation != "genoa" {
		t.Fatalf("Evidence() = %q, %q, %q", ev, platform, generation)
	}
	if string(gotReq.ReportData.Bytes()) != "report-data" {
		t.Fatalf("report_data not forwarded: %q", gotReq.ReportData.Bytes())
	}
}

func TestLiveEvidenceProviderPlatformFallback(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No platform in the response: the provider must fall back to its own.
		json.NewEncoder(w).Encode(types.AttestResponse{Evidence: json.RawMessage(`{}`)})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: attestationclient.NewClient(api.URL), Platform: types.PlatformSnp, Generation: "genoa"}
	_, platform, _, err := p.Evidence(context.Background(), []byte("rd"))
	if err != nil {
		t.Fatal(err)
	}
	if platform != string(types.PlatformSnp) {
		t.Fatalf("platform = %q, want fallback %q", platform, types.PlatformSnp)
	}
}

func TestLiveEvidenceProviderError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: attestationclient.NewClient(api.URL), Platform: types.PlatformSnp}
	_, _, _, err := p.Evidence(context.Background(), []byte("rd"))
	if err == nil || !strings.Contains(err.Error(), "attestation-api") {
		t.Fatalf("expected attestation-api error, got %v", err)
	}
}

// The real bare-metal evidence shared with localverify's tests: its report can
// be paired with its true VCEK by a KDS-stubbed embedder.
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

type cannedGetter struct {
	body []byte
	err  error
}

func (g cannedGetter) Get(string) ([]byte, error) { return g.body, g.err }

func chainlessEvidenceAPI(t *testing.T, evidence json.RawMessage) *httptest.Server {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(types.AttestResponse{Platform: "snp", Evidence: evidence})
	}))
	t.Cleanup(api.Close)
	return api
}

func TestLiveEvidenceProviderEmbedsVCEK(t *testing.T) {
	chainless, vcekDER := loadSnpFixture(t)
	api := chainlessEvidenceAPI(t, chainless)

	p := LiveEvidenceProvider{
		Client:     attestationclient.NewClient(api.URL),
		Platform:   types.PlatformSnp,
		Generation: "genoa",
		VCEK:       snpvcek.NewWithGetter(cannedGetter{body: vcekDER}),
	}
	ev, _, _, err := p.Evidence(context.Background(), []byte("rd"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		CertChain struct {
			Vcek string `json:"vcek"`
		} `json:"cert_chain"`
	}
	if err := json.Unmarshal(ev, &got); err != nil {
		t.Fatal(err)
	}
	if got.CertChain.Vcek != base64.StdEncoding.EncodeToString(vcekDER) {
		t.Fatalf("cert_chain.vcek = %q, want the embedded VCEK", got.CertChain.Vcek)
	}
}

func TestLiveEvidenceProviderServesChainlessWhenKDSUnreachable(t *testing.T) {
	chainless, _ := loadSnpFixture(t)
	api := chainlessEvidenceAPI(t, chainless)

	p := LiveEvidenceProvider{
		Client:     attestationclient.NewClient(api.URL),
		Platform:   types.PlatformSnp,
		Generation: "genoa",
		VCEK:       snpvcek.NewWithGetter(cannedGetter{err: errors.New("kds unreachable")}),
	}
	ev, _, _, err := p.Evidence(context.Background(), []byte("rd"))
	if err != nil {
		t.Fatalf("a failed embed must not fail the request: %v", err)
	}
	if string(ev) != string(chainless) {
		t.Fatalf("evidence = %s, want the original chainless evidence", ev)
	}
}
