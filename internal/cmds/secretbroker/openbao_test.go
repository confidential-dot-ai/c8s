package secretbroker

import (
	"strings"
	"testing"
	"time"
)

func TestParseMeasurementsBytes(t *testing.T) {
	valid := strings.Repeat("ab", 48)
	got, err := parseMeasurementsBytes([]string{"  " + strings.ToUpper(valid) + "  "})
	if err != nil {
		t.Fatalf("valid SHA-384 measurement rejected: %v", err)
	}
	if len(got) != 1 || len(got[0]) != 48 {
		t.Fatalf("parsed measurements = %#v, want one 48-byte value", got)
	}

	for _, measurement := range []string{"", "   ", "00", strings.Repeat("z", 96)} {
		t.Run(measurement, func(t *testing.T) {
			if _, err := parseMeasurementsBytes([]string{measurement}); err == nil {
				t.Fatalf("parseMeasurementsBytes(%q) succeeded, want error", measurement)
			}
		})
	}
}

func TestValidateConfigRequiresMeasurements(t *testing.T) {
	valid := strings.Repeat("ab", 48)
	base := config{
		peerVerify:      peerVerifyCA,
		clientCA:        "ca.pem",
		openbaoAttested: false,
		openbaoToken:    "test-token",
		tokenTTL:        time.Minute,
		maxRequestSize:  1,
	}

	t.Run("caller", func(t *testing.T) {
		cfg := base
		cfg.peerVerify = peerVerifyRATLS
		if err := validateConfig(cfg); err == nil {
			t.Fatal("validateConfig accepted ratls caller verification without measurements")
		}
		cfg.measurements = []string{valid}
		if err := validateConfig(cfg); err != nil {
			t.Fatalf("validateConfig rejected pinned caller measurement: %v", err)
		}
	})

	t.Run("store", func(t *testing.T) {
		cfg := base
		cfg.openbaoAttested = true
		if err := validateConfig(cfg); err == nil {
			t.Fatal("validateConfig accepted attested store verification without measurements")
		}
		cfg.openbaoMeasurements = []string{valid}
		if err := validateConfig(cfg); err != nil {
			t.Fatalf("validateConfig rejected pinned store measurement: %v", err)
		}
	})
}
