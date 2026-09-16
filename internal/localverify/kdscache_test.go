package localverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

func TestDefaultKDSCacheDir_EnvOverrideAndDisable(t *testing.T) {
	t.Setenv(kdsCacheDirEnv, "/tmp/c8s-kds-test")
	if got := defaultKDSCacheDir(); got != "/tmp/c8s-kds-test" {
		t.Fatalf("override: got %q", got)
	}
	t.Setenv(kdsCacheDirEnv, "")
	if got := defaultKDSCacheDir(); got != "" {
		t.Fatalf("empty override must disable the cache, got %q", got)
	}
}

// mapGetter is a fake KDS: it serves exactly the URLs it holds and counts hits.
type mapGetter struct {
	calls map[string]int
	body  map[string][]byte
}

func (g *mapGetter) Get(url string) ([]byte, error) {
	g.calls[url]++
	if b, ok := g.body[url]; ok {
		return b, nil
	}
	return nil, errors.New("404")
}

// TestVerify_BareSNPEvidence_VCEKFromCacheAfterFirstFetch runs the real
// verifier over real Genoa evidence with its inline VCEK stripped, the way a
// bare RA-TLS serving cert arrives: the first Verify fetches the VCEK from a
// fake KDS under the URL go-sev-guest derives from the report, the second
// Verify runs with KDS unavailable and must still succeed from the shared cache.
func TestVerify_BareSNPEvidence_VCEKFromCacheAfterFirstFetch(t *testing.T) {
	platform, evidence := envelopeFixture(t, "snp-evidence-genoa.json")
	var ev struct {
		Report    string `json:"attestation_report"`
		CertChain struct {
			Vcek string `json:"vcek"`
		} `json:"cert_chain"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil {
		t.Fatal(err)
	}
	vcek, err := base64.StdEncoding.DecodeString(ev.CertChain.Vcek)
	if err != nil {
		t.Fatal(err)
	}
	reportBytes, err := base64.StdEncoding.DecodeString(ev.Report)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := abi.ReportToProto(reportBytes)
	if err != nil {
		t.Fatal(err)
	}
	url := kds.VCEKCertURL("Genoa", rp.GetChipId(), kds.TCBVersion(rp.GetReportedTcb()))
	bare, err := json.Marshal(map[string]string{"attestation_report": ev.Report})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	t.Setenv(kdsCacheDirEnv, dir)
	fake := &mapGetter{calls: map[string]int{}, body: map[string][]byte{url: vcek}}
	orig := kdsGetter
	t.Cleanup(func() { kdsGetter = orig })
	kdsGetter = func() trust.HTTPSGetter { return fake }

	res, err := Verify(context.Background(), platform, bare, Params{})
	if err != nil {
		t.Fatalf("first verification (VCEK from fake KDS): %v", err)
	}
	if !res.SignatureValid {
		t.Fatal("signature_valid must be true")
	}
	if fake.calls[url] != 1 {
		t.Fatalf("KDS fetched %d times for %s, want 1", fake.calls[url], url)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("cache holds %d entries, want the one VCEK", len(entries))
	}
	if cached, _ := os.ReadFile(filepath.Join(dir, entries[0].Name())); !bytes.Equal(cached, vcek) {
		t.Fatal("cached bytes are not the VCEK the fake KDS served")
	}

	throttled := &mapGetter{calls: map[string]int{}, body: nil}
	kdsGetter = func() trust.HTTPSGetter { return throttled }
	res, err = Verify(context.Background(), platform, bare, Params{})
	if err != nil {
		t.Fatalf("second verification with KDS down must be served from the cache: %v", err)
	}
	if !res.SignatureValid {
		t.Fatal("signature_valid must be true on the cached path")
	}
	if len(throttled.calls) != 0 {
		t.Fatalf("second verification reached KDS: %v", throttled.calls)
	}
}
