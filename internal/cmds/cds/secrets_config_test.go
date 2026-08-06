package cds

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// secretsReadyConfig can serve /secrets: sandbox identity is fully configured
// and no handoff is set.
func secretsReadyConfig() config {
	return config{
		ratlsPlatform:        "sev-snp",
		measurements:         []string{strings.Repeat("ab", 48)},
		inventoryCIDRs:       []string{"10.0.0.0/24"},
		secretsMaxPaths:      16,
		secretsMaxValueBytes: 64,
		sandboxLedgerMax:     16,
	}
}

func testInventoryHosts(t *testing.T) workloadclaims.InventoryHosts {
	t.Helper()
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	return hosts
}

// A fully-configured CDS serves /secrets with no flag to turn it on: release is
// gated on an allowlist entry carrying a grant, not on configuration.
func TestSecretsEnabledWhenSandboxIdentityWorks(t *testing.T) {
	enabled, why := secretsEnabled(secretsReadyConfig(), &workloadclaims.DigestsClient{}, testInventoryHosts(t))
	if !enabled {
		t.Fatalf("secrets not served on a fully configured CDS: %s", why)
	}
}

// Each of these leaves CDS unable to establish what a sandbox runs, so it must
// not answer at all rather than answer badly.
func TestSecretsDisabledWhenItCannotAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    func(*config)
		client *workloadclaims.DigestsClient
		want   string
	}{
		{"no platform", func(*config) {}, nil, "--ratls-platform"},
		{"no measurements", func(c *config) { c.measurements = nil }, &workloadclaims.DigestsClient{}, "--measurements"},
		{"handoff peer", func(c *config) { c.handoffPeerURL = "https://cds.example" }, &workloadclaims.DigestsClient{}, "handoff"},
		{"handoff measurements", func(c *config) { c.handoffMeasurements = []string{"ab"} }, &workloadclaims.DigestsClient{}, "handoff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := secretsReadyConfig()
			tc.cfg(&cfg)
			enabled, why := secretsEnabled(cfg, tc.client, testInventoryHosts(t))
			if enabled {
				t.Fatal("secrets served despite the prerequisite being unmet")
			}
			if !strings.Contains(why, tc.want) {
				t.Fatalf("reason %q does not mention %q", why, tc.want)
			}
		})
	}
}

// Without a bound there is nothing constraining which address the callback
// may dial.
func TestSecretsDisabledWithoutInventoryCIDRs(t *testing.T) {
	enabled, why := secretsEnabled(secretsReadyConfig(), &workloadclaims.DigestsClient{}, nil)
	if enabled || !strings.Contains(why, "no node addresses") {
		t.Fatalf("enabled=%v reason=%q", enabled, why)
	}
}

// Handoff is checked before anything else: it is the one case where CDS could
// answer but must not, so its reason has to be the one an operator sees.
func TestHandoffReasonWinsOverOtherGaps(t *testing.T) {
	cfg := secretsReadyConfig()
	cfg.handoffPeerURL = "https://cds.example"
	cfg.measurements = nil
	if _, why := secretsEnabled(cfg, nil, nil); !strings.Contains(why, "handoff") {
		t.Fatalf("reason = %q, want the handoff refusal", why)
	}
}

func TestSecretsSizingMustBePositive(t *testing.T) {
	for _, brk := range []func(*config){
		func(c *config) { c.secretsMaxPaths = 0 },
		func(c *config) { c.secretsMaxValueBytes = 0 },
		func(c *config) { c.sandboxLedgerMax = 0 },
	} {
		cfg := secretsReadyConfig()
		brk(&cfg)
		if err := validateSecretsConfig(cfg); err == nil {
			t.Fatal("a non-positive bound was accepted")
		}
	}
	if err := validateSecretsConfig(secretsReadyConfig()); err != nil {
		t.Fatalf("valid bounds refused: %v", err)
	}
}
