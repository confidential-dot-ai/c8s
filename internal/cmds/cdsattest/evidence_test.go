package cdsattest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	ev, err := p.Evidence(context.Background(), []byte("ignored"))
	if err != nil || string(ev.Evidence) != raw || ev.Platform != "snp" || ev.Generation != "genoa" {
		t.Fatalf("Evidence() = %+v, %v", ev, err)
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
	gpu := json.RawMessage(`{"devices":[{"arch":"BLACKWELL","uuid":"gpu-1"}],"binding":{"kind":"concat","algo":"sha256"}}`)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/attest" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(types.AttestResponse{
			Platform:    "snp",
			Evidence:    json.RawMessage(`{"attestation_report":"AAAA"}`),
			GPUAttested: types.GPUAttestedEvidenceCollected,
			NvidiaGPU:   gpu,
		})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{
		Client:            attestationclient.NewClient(api.URL),
		Platform:          types.PlatformSnp,
		Generation:        "genoa",
		NvidiaGPUEvidence: true,
	}
	ev, err := p.Evidence(context.Background(), []byte("report-data"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ev.Evidence) != `{"attestation_report":"AAAA"}` || ev.Platform != "snp" || ev.Generation != "genoa" {
		t.Fatalf("Evidence() = %+v", ev)
	}
	if string(gotReq.ReportData.Bytes()) != "report-data" {
		t.Fatalf("report_data not forwarded: %q", gotReq.ReportData.Bytes())
	}
	if !gotReq.NvidiaGPU || ev.GPUAttested != types.GPUAttestedEvidenceCollected || string(ev.NvidiaGPU) != string(gpu) {
		t.Fatalf("GPU evidence changed: request=%t status=%q bundle=%s", gotReq.NvidiaGPU, ev.GPUAttested, ev.NvidiaGPU)
	}
}

func TestLiveEvidenceProviderPlatformFallback(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No platform in the response: the provider must fall back to its own.
		json.NewEncoder(w).Encode(types.AttestResponse{Evidence: json.RawMessage(`{}`)})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: attestationclient.NewClient(api.URL), Platform: types.PlatformSnp, Generation: "genoa"}
	got, err := p.Evidence(context.Background(), []byte("rd"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != string(types.PlatformSnp) {
		t.Fatalf("platform = %q, want fallback %q", got.Platform, types.PlatformSnp)
	}
}

func TestLiveEvidenceProviderError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: attestationclient.NewClient(api.URL), Platform: types.PlatformSnp}
	_, err := p.Evidence(context.Background(), []byte("rd"))
	if err == nil || !strings.Contains(err.Error(), "attestation-api") {
		t.Fatalf("expected attestation-api error, got %v", err)
	}
}
