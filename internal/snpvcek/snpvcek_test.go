package snpvcek

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

// The Genoa fixture is real bare-metal evidence (report v5, Zen4c CPUID
// family 0x19 model 0xA0) shared with the localverify tests.
const fixturePath = "../localverify/testdata/snp-evidence-genoa.json"

// fixture returns the fixture's evidence without its cert_chain, plus the
// stripped VCEK DER.
func fixture(t *testing.T) (chainless json.RawMessage, vcekDER []byte) {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
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
		"cert_chain":         nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return chainless, vcekDER
}

// testReport synthesizes a minimal report for the shapes the fixture cannot
// cover (VLEK signer, v2 without CPUID).
func testReport(t *testing.T, version byte) []byte {
	t.Helper()
	raw := make([]byte, abi.ReportSize)
	raw[0] = version
	raw[0x08+2] = 0x02 // policy bit 17 (reserved-must-be-one)
	raw[0x34] = 1      // signature algo: ECDSA P-384
	if version >= 3 {
		raw[0x188], raw[0x189], raw[0x18A] = 0x19, 0xA0, 0x02 // Zen4c CPUID
	}
	copy(raw[0x180:0x188], []byte{0x0c, 0, 0, 0, 0, 0, 0x1c, 0x1c}) // reported TCB
	for i := 0; i < 64; i++ {
		raw[0x1A0+i] = byte(i + 1) // chip id
	}
	if _, err := abi.ReportToProto(raw); err != nil {
		t.Fatalf("synthesized report does not parse: %v", err)
	}
	return raw
}

func syntheticEvidence(t *testing.T, report []byte) json.RawMessage {
	t.Helper()
	ev, err := json.Marshal(map[string]any{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-the-vcek"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeGetter serves canned bytes and records requested URLs.
type fakeGetter struct {
	urls []string
	body []byte
	err  error
}

func (g *fakeGetter) Get(url string) ([]byte, error) {
	g.urls = append(g.urls, url)
	if g.err != nil {
		return nil, g.err
	}
	return g.body, nil
}

func TestEmbedNonSnpPassthrough(t *testing.T) {
	g := &fakeGetter{}
	e := NewWithGetter(g)
	in := json.RawMessage(`{"anything":"at-all"}`)
	out, err := e.Embed(context.Background(), "az-snp", in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("Embed() = %q, %v; want passthrough", out, err)
	}
	if len(g.urls) != 0 {
		t.Fatalf("getter consulted for non-snp platform: %v", g.urls)
	}
}

func TestEmbedExistingChainPassthrough(t *testing.T) {
	g := &fakeGetter{}
	e := NewWithGetter(g)
	in := json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)
	out, err := e.Embed(context.Background(), "snp", in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("Embed() = %q, %v; want passthrough", out, err)
	}
	if len(g.urls) != 0 {
		t.Fatalf("getter consulted despite inline VCEK: %v", g.urls)
	}
}

// The embedded output must verify fully offline: a cancelled context makes
// localverify's KDS-fetch path fail, so success proves the inline-VCEK
// envelope path (the same property c8s-verify-js relies on).
func TestEmbedOutputVerifiesOffline(t *testing.T) {
	chainless, vcekDER := fixture(t)
	g := &fakeGetter{body: vcekDER}
	e := NewWithGetter(g)

	out, err := e.Embed(context.Background(), "snp", chainless)
	if err != nil {
		t.Fatal(err)
	}

	// Zen4c collateral is served under the Genoa product line.
	wantURL := "https://kdsintf.amd.com/vcek/v1/Genoa/" +
		"b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0" +
		"d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce" +
		"?blSPL=10&teeSPL=0&snpSPL=27&ucodeSPL=27"
	if len(g.urls) != 1 || g.urls[0] != wantURL {
		t.Fatalf("KDS URL(s) = %v, want [%s]", g.urls, wantURL)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := localverify.Verify(ctx, "snp", out, localverify.Params{})
	if err != nil {
		t.Fatalf("embedded evidence must verify offline: %v", err)
	}
	if !res.SignatureValid {
		t.Fatal("signature_valid must be true")
	}

	// Second call is served from the cache.
	if _, err := e.Embed(context.Background(), "snp", chainless); err != nil {
		t.Fatal(err)
	}
	if len(g.urls) != 1 {
		t.Fatalf("getter consulted on cache hit: %v", g.urls)
	}
}

func TestEmbedFailureReturnsOriginalAndBacksOff(t *testing.T) {
	chainless, vcekDER := fixture(t)
	g := &fakeGetter{err: errors.New("kds down")}
	e := NewWithGetter(g)

	out, err := e.Embed(context.Background(), "snp", chainless)
	if err == nil || string(out) != string(chainless) {
		t.Fatalf("Embed() = %q, %v; want original evidence + error", out, err)
	}
	if len(g.urls) != 1 {
		t.Fatalf("getter calls = %v, want 1", g.urls)
	}

	// Within the backoff window the getter is not consulted again.
	if _, err := e.Embed(context.Background(), "snp", chainless); err == nil {
		t.Fatal("want error during backoff")
	}
	if len(g.urls) != 1 {
		t.Fatalf("getter consulted during backoff: %v", g.urls)
	}

	// After the backoff expires (and KDS recovers) the fetch succeeds.
	e.lastFailure = time.Now().Add(-2 * failureBackoff)
	g.err = nil
	g.body = vcekDER
	if _, err := e.Embed(context.Background(), "snp", chainless); err != nil {
		t.Fatal(err)
	}
	if len(g.urls) != 2 {
		t.Fatalf("getter not consulted after backoff: %v", g.urls)
	}
}

func TestEmbedRejectsNonCertificate(t *testing.T) {
	chainless, _ := fixture(t)
	g := &fakeGetter{body: []byte("<html>rate limited</html>")}
	e := NewWithGetter(g)
	out, err := e.Embed(context.Background(), "snp", chainless)
	if err == nil || string(out) != string(chainless) {
		t.Fatalf("Embed() = %q, %v; want original evidence + error", out, err)
	}
	if e.cachedDER != nil {
		t.Fatal("garbage response was cached")
	}
}

func TestEmbedRejectsCertificateThatDidNotSignReport(t *testing.T) {
	chainless, _ := fixture(t)
	g := &fakeGetter{body: selfSignedDER(t)}
	e := NewWithGetter(g)
	out, err := e.Embed(context.Background(), "snp", chainless)
	if err == nil || string(out) != string(chainless) {
		t.Fatalf("Embed() = %q, %v; want original evidence + error", out, err)
	}
	if e.cachedDER != nil {
		t.Fatal("mismatched certificate was cached")
	}
}

// A VLEK-signed report has no KDS-fetchable cert: Embed must fail without a
// fetch, and without arming the backoff.
func TestEmbedVlekSignedReport(t *testing.T) {
	raw := testReport(t, 3)
	raw[0x48] = 0x04 // signer_info: signing key = VLEK
	g := &fakeGetter{}
	e := NewWithGetter(g)
	out, err := e.Embed(context.Background(), "snp", syntheticEvidence(t, raw))
	if err == nil {
		t.Fatalf("want error for a VLEK-signed report, got %q", out)
	}
	if len(g.urls) != 0 {
		t.Fatalf("getter consulted for a VLEK report: %v", g.urls)
	}
	if !e.lastFailure.IsZero() {
		t.Fatal("backoff armed without a KDS attempt")
	}
}

// Bare-metal verification requires report v3+; a v2 report must fail without
// a fetch (its KDS URL is not derivable — no CPUID product info).
func TestEmbedV2ReportRejected(t *testing.T) {
	g := &fakeGetter{}
	e := NewWithGetter(g)
	_, err := e.Embed(context.Background(), "snp", syntheticEvidence(t, testReport(t, 2)))
	if err == nil {
		t.Fatal("want error for a v2 report")
	}
	if len(g.urls) != 0 {
		t.Fatalf("getter consulted for a v2 report: %v", g.urls)
	}
}

func TestEmbedMalformedEvidence(t *testing.T) {
	e := NewWithGetter(&fakeGetter{})
	for _, in := range []string{`[]`, `{"attestation_report":42}`, `{"attestation_report":"!!!"}`, `{"attestation_report":"AAAA"}`} {
		out, err := e.Embed(context.Background(), "snp", json.RawMessage(in))
		if err == nil || string(out) != in {
			t.Fatalf("Embed(%q) = %q, %v; want original + error", in, out, err)
		}
	}
}
