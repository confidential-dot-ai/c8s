package sidecar

import (
	"encoding/hex"
	"strings"
	"testing"
)

func measurementHex() string { return strings.Repeat(hex.EncodeToString([]byte{0xab}), 48) }

// Empty measurements accept any RA-TLS-attested CDS, so dropping the flag is
// how a host points a sidecar at a CDS it runs. Under kata it writes the argv.
func TestParseMeasurementsRefusesAnUnpinnedCDSInsideAKataGuest(t *testing.T) {
	cfg := Config{WorkloadClaimsGuest: true}
	if _, err := cfg.ParseMeasurements(); err == nil || !strings.Contains(err.Error(), "--measurements is empty") {
		t.Fatalf("error = %v, want a refusal to use an unpinned CDS", err)
	}
}

// Outside kata "no pinning" is a supported development shape.
func TestParseMeasurementsWarnsOutsideAKataGuest(t *testing.T) {
	cfg := Config{}
	got, err := cfg.ParseMeasurements()
	if err != nil {
		t.Fatalf("ParseMeasurements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("parsed %d measurements, want none", len(got))
	}
}

func TestParseMeasurementsAcceptsAPinnedCDSInsideAKataGuest(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, WorkloadClaimsGuest: true}
	got, err := cfg.ParseMeasurements()
	if err != nil {
		t.Fatalf("ParseMeasurements: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d measurements, want 1", len(got))
	}
}

func TestParseMeasurementsRejectsMalformedHex(t *testing.T) {
	cfg := Config{Measurements: []string{"zz"}}
	if _, err := cfg.ParseMeasurements(); err == nil || !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}
