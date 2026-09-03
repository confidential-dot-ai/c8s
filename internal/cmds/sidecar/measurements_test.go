package sidecar

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func measurementHex() string { return strings.Repeat(hex.EncodeToString([]byte{0xab}), 48) }

// Empty measurements accept any RA-TLS-attested CDS, so dropping the flag is
// how a host points a sidecar at a CDS it runs. Under kata it writes the argv.
func TestCDSPinsRefusesAnUnpinnedCDSInsideAKataGuest(t *testing.T) {
	cfg := Config{WorkloadClaimsGuest: true}
	if _, err := cfg.CDSPins(t.Context()); err == nil || !strings.Contains(err.Error(), "--measurements is empty") {
		t.Fatalf("error = %v, want a refusal to use an unpinned CDS", err)
	}
}

// Outside kata "no pinning" is a supported development shape.
func TestCDSPinsWarnsOutsideAKataGuest(t *testing.T) {
	cfg := Config{}
	got, err := cfg.CDSPins(t.Context())
	if err != nil {
		t.Fatalf("CDSPins: %v", err)
	}
	if len(got.Measurements) != 0 {
		t.Fatalf("parsed %d measurements, want none", len(got.Measurements))
	}
}

func TestCDSPinsAcceptsAPinnedCDSInsideAKataGuest(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, WorkloadClaimsGuest: true}
	got, err := cfg.CDSPins(t.Context())
	if err != nil {
		t.Fatalf("CDSPins: %v", err)
	}
	if len(got.Measurements) != 1 {
		t.Fatalf("parsed %d measurements, want 1", len(got.Measurements))
	}
}

func TestCDSPinsRejectsMalformedHex(t *testing.T) {
	cfg := Config{Measurements: []string{"zz"}}
	if _, err := cfg.CDSPins(t.Context()); err == nil || !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}

func TestCDSPinsRejectsMalformedRTMR(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, RTMRs: []string{"1=zz"}}
	if _, err := cfg.CDSPins(t.Context()); err == nil || !strings.Contains(err.Error(), "--rtmrs") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}

// A sealed node's sidecar takes its CDS pins from its own quote: the flat
// flags would put a cluster-specific digest into an argv the bundle measures.
func TestCDSPinsFromOwnQuote(t *testing.T) {
	reg := func(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 48) }
	stub, url := testattest.NewUnix(t)
	stub.SetPlatform(types.PlatformTdx)
	stub.SetVerdict(testattest.TDXVerdict(reg(0x11), map[int]string{0: reg(0), 1: reg(0x21), 2: reg(0x22), 3: reg(0x33)}))
	cfg := Config{AttestationApiURL: url, CDSPinsFromOwnQuote: true}
	got, err := cfg.CDSPins(t.Context())
	if err != nil {
		t.Fatalf("CDSPins(own quote) = %v, want nil", err)
	}
	if len(got.Entries) != 1 || len(got.Measurements) != 0 || len(got.RTMRs) != 0 {
		t.Fatalf("CDSPins(own quote) = %+v, want exactly one entry and no loose pins", got)
	}
	if e := got.Entries[0]; hex.EncodeToString(e.Digest) != reg(0x11) || hex.EncodeToString(e.RTMRs[3]) != reg(0x33) {
		t.Fatalf("CDSPins(own quote) entry = %x / RTMR[3] %x, want the quote's tuple", e.Digest, e.RTMRs[3])
	}
}

func TestCDSPinsFromOwnQuoteNeedsAVerifier(t *testing.T) {
	stub, url := testattest.NewUnix(t)
	stub.SetVerdict(testattest.PassingVerdict(strings.Repeat("11", 48))) // snp: no registers
	cfg := Config{AttestationApiURL: url, CDSPinsFromOwnQuote: true}
	if _, err := cfg.CDSPins(t.Context()); err == nil || !strings.Contains(err.Error(), "--cds-pins-from-own-quote") {
		t.Fatalf("CDSPins(snp verifier) = %v, want a failure naming the flag", err)
	}
}

// The own-quote flag and the flat pins are two answers to one question, and
// the quote is only trustworthy from the node's own verifier.
func TestValidateOwnQuoteFlagRules(t *testing.T) {
	base := Config{CDSURL: "https://cds:8443", Attempts: 1, RetryInterval: 1, RequestTimeout: 1, InventoryTimeout: 1, CDSPinsFromOwnQuote: true}
	for _, tc := range []struct {
		name    string
		edit    func(c *Config)
		wantErr string
	}{
		{"unix verifier", func(c *Config) { c.AttestationApiURL = "unix:///run/confai/attestation-api.sock" }, ""},
		{"with measurements", func(c *Config) {
			c.AttestationApiURL = "unix:///run/confai/attestation-api.sock"
			c.Measurements = []string{measurementHex()}
		}, "replaces --measurements"},
		{"with rtmrs", func(c *Config) {
			c.AttestationApiURL = "unix:///run/confai/attestation-api.sock"
			c.RTMRs = []string{"1=" + measurementHex()}
		}, "replaces --measurements"},
		{"network verifier", func(c *Config) { c.AttestationApiURL = "http://127.0.0.1:8400" }, "unix://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			err := cfg.Validate()
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Validate(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
		})
	}
}
