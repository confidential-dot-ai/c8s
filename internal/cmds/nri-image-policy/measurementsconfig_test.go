package nriimagepolicy

import (
	"testing"
)

func TestPullAndInventoryUseCompleteCDSPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "../../../internal/testdata/node-identities.json"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// Both the pull client and inventory endpoint call this resolver.
	pins, err := cfg.Allowlist.Pull.cdsPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(pins.Images) != 2 || len(pins.Images[0].Anchor) == 0 || len(pins.Images[0].RTMRs) != 2 {
		t.Fatal("CDS policy lost part of its image/operator tuple")
	}
	if _, err := allowlistPullHTTPClient(cfg.Allowlist.Pull); err != nil {
		t.Fatal(err)
	}
	cfg.Allowlist.Pull.CDSMeasurements = []string{"ab"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("mixed full and flat policies accepted")
	}
	if _, err := cfg.Allowlist.Pull.cdsPins(); err == nil {
		t.Fatal("inventory resolver accepted mixed policies")
	}
	cfg.Allowlist.Pull.CDSMeasurements = nil
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "missing-file"
	if _, err := cfg.Allowlist.Pull.cdsPins(); err == nil {
		t.Fatal("missing full policy fell back to unpinned")
	}
}
