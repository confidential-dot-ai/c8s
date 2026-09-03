package getcert

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The own-quote flag and the flat pins are two answers to one question, and
// the quote is only trustworthy from the node's own verifier.
func TestValidateConfigOwnQuoteFlagRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(c *config)
		wantErr string
	}{
		{"unix verifier", func(*config) {}, ""},
		{"with cds-measurements", func(c *config) { c.CDSMeasurements = strings.Repeat("ab", 48) }, "replaces --cds-measurements"},
		{"with cds-rtmrs", func(c *config) { c.CDSRTMRs = "1=" + strings.Repeat("ab", 48) }, "replaces --cds-measurements"},
		{"network verifier", func(c *config) { c.AttestationApiURL = "http://127.0.0.1:8400" }, "unix://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{
				CDSURL:              "https://cds:8443",
				AttestationApiURL:   "unix:///run/confai/attestation-api.sock",
				SAN:                 "host.example.com",
				CDSPinsFromOwnQuote: true,
			}
			tc.edit(&cfg)
			err := validateConfig(cfg)
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("validateConfig(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
		})
	}
}

// Under the flag the CDS client is pinned to the tuple the node's verifier
// reports for this pod: one whole entry, no loose pins, and no "unpinned"
// warning since the pin is a real one.
func TestCDSHTTPClientPinsFromOwnQuote(t *testing.T) {
	reg := func(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 48) }
	stub, url := testattest.NewUnix(t)
	stub.SetPlatform(types.PlatformTdx)
	stub.SetVerdict(testattest.TDXVerdict(reg(0x11), map[int]string{0: reg(0), 1: reg(0x21), 2: reg(0x22), 3: reg(0x33)}))
	cfg := config{CDSURL: "https://cds:8443", AttestationApiURL: url, CDSPinsFromOwnQuote: true}

	c := captureDefaultLogger(t)
	pins, err := cdsPins(t.Context(), cfg)
	if err != nil {
		t.Fatalf("cdsPins(own quote) = %v, want nil", err)
	}
	if len(pins.Entries) != 1 || len(pins.Measurements) != 0 || len(pins.RTMRs) != 0 {
		t.Fatalf("cdsPins(own quote) = %+v, want exactly one entry and no loose pins", pins)
	}
	if e := pins.Entries[0]; hex.EncodeToString(e.Digest) != reg(0x11) || hex.EncodeToString(e.RTMRs[3]) != reg(0x33) {
		t.Fatalf("cdsPins(own quote) entry = %x / RTMR[3] %x, want the quote's tuple", e.Digest, e.RTMRs[3])
	}
	if _, ok := c.find("--cds-measurements not set"); ok {
		t.Fatal("warned about an unpinned CDS although the own-quote pin is set")
	}
	if _, err := cdsHTTPClient(t.Context(), cfg); err != nil {
		t.Fatalf("cdsHTTPClient(own quote) = %v, want nil", err)
	}

	stub.SetPlatform(types.PlatformSnp)
	if _, err := cdsHTTPClient(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "--cds-pins-from-own-quote") {
		t.Fatalf("cdsHTTPClient(snp verifier) = %v, want a failure naming the flag", err)
	}
}

// The self-attestation runs under the caller's context so a SIGTERM during a
// slow verifier answer ends the sidecar instead of waiting out
// ownQuoteTimeout.
func TestCDSPinsFromOwnQuoteHonorsContext(t *testing.T) {
	stub, url := testattest.NewUnix(t)
	stub.SetPlatform(types.PlatformTdx)
	cfg := config{CDSURL: "https://cds:8443", AttestationApiURL: url, CDSPinsFromOwnQuote: true}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := cdsPins(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cdsPins(cancelled ctx) = %v, want %v", err, context.Canceled)
	}
	if n := len(stub.AttestRequests()); n != 0 {
		t.Fatalf("attest requests under a cancelled context = %d, want 0", n)
	}
}
