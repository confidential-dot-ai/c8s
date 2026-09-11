package getcert

import (
	"strings"
	"testing"
)

func TestUnpinnedCDSAllowed(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}

// A pinned measurement is what the flag is for; it must still work.
func TestPinnedCDSAccepted(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		CDSMeasurements:   strings.Repeat("ab", 48),
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
