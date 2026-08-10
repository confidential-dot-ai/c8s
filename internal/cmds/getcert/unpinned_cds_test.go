package getcert

import (
	"strings"
	"testing"
)

// Empty measurements accept any RA-TLS-attested CDS. Under kata the host writes
// this argv, so dropping the flag is how it points the sidecar at a CDS it runs.
func TestUnpinnedCDSRefusedInsideAKataGuest(t *testing.T) {
	cfg := config{
		CDSURL:              "https://cds:8443",
		AttestationApiURL:   "http://attestation-api:8400",
		SAN:                 "host.example.com",
		WorkloadClaimsGuest: true,
	}
	_, err := cdsHTTPClient(cfg)
	if err == nil || !strings.Contains(err.Error(), "--measurements is empty") {
		t.Fatalf("error = %v, want a refusal to use an unpinned CDS", err)
	}
}

// Outside kata "no pinning" stays a supported development shape.
func TestUnpinnedCDSAllowedOutsideAKataGuest(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}

// A pinned measurement is what the flag is for; it must still work under kata.
func TestPinnedCDSAcceptedInsideAKataGuest(t *testing.T) {
	cfg := config{
		CDSURL:              "https://cds:8443",
		AttestationApiURL:   "http://attestation-api:8400",
		SAN:                 "host.example.com",
		CDSMeasurements:     strings.Repeat("ab", 48),
		WorkloadClaimsGuest: true,
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
