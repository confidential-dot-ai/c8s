package sidecar

import (
	"encoding/hex"
	"strings"
	"testing"
)

func measurementHex() string { return strings.Repeat(hex.EncodeToString([]byte{0xab}), 48) }

// Empty measurements accept any RA-TLS-attested CDS, so dropping the flag is
// how a host points a sidecar at a CDS it runs. Under kata it writes the argv.
func TestParsePinsRefusesAnUnpinnedCDSInsideAKataGuest(t *testing.T) {
	cfg := Config{WorkloadClaimsGuest: true}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--measurements is empty") {
		t.Fatalf("error = %v, want a refusal to use an unpinned CDS", err)
	}
}

// Outside kata "no pinning" is a supported development shape.
func TestParsePinsWarnsOutsideAKataGuest(t *testing.T) {
	cfg := Config{}
	got, err := cfg.ParsePins()
	if err != nil {
		t.Fatalf("ParsePins: %v", err)
	}
	if len(got.Measurements) != 0 {
		t.Fatalf("parsed %d measurements, want none", len(got.Measurements))
	}
}

func TestParsePinsAcceptsAPinnedCDSInsideAKataGuest(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, WorkloadClaimsGuest: true}
	got, err := cfg.ParsePins()
	if err != nil {
		t.Fatalf("ParsePins: %v", err)
	}
	if len(got.Measurements) != 1 {
		t.Fatalf("parsed %d measurements, want 1", len(got.Measurements))
	}
}

func TestParsePinsRejectsMalformedHex(t *testing.T) {
	cfg := Config{Measurements: []string{"zz"}}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}

func TestParsePinsRejectsMalformedRTMR(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, RTMRs: []string{"1=zz"}}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--rtmrs") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}

func TestParsePinsRejectsMalformedPCRAndInitData(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, PCRs: []string{"8=zz"}}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--pcrs") {
		t.Fatalf("error = %v, want a PCR parse error naming the flag", err)
	}
	cfg = Config{Measurements: []string{measurementHex()}, InitDataHash: "zz"}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--init-data-hash") {
		t.Fatalf("error = %v, want an init-data parse error naming the flag", err)
	}
}
