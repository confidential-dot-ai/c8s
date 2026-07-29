package cds

import (
	"strings"
	"testing"
)

// secretsConfig is a --secrets configuration with everything satisfied, so each
// case below can remove exactly one requirement.
func secretsConfig() config {
	return config{
		secrets:                 true,
		ratlsPlatform:           "sev-snp",
		measurements:            []string{strings.Repeat("ab", 48)},
		inventoryCIDRs:          []string{"10.0.0.0/24"},
		injectedComponentDigest: []string{"sha256:" + strings.Repeat("1", 64)},
		secretsMaxPaths:         16,
		secretsMaxValueBytes:    64,
		sandboxLedgerMax:        16,
	}
}

func TestSecretsConfigAccepted(t *testing.T) {
	if err := validateSecretsConfig(secretsConfig()); err != nil {
		t.Fatalf("a fully configured --secrets was refused: %v", err)
	}
}

func TestSecretsDisabledSkipsChecks(t *testing.T) {
	if err := validateSecretsConfig(config{}); err != nil {
		t.Fatalf("--secrets off should require nothing: %v", err)
	}
}

// Each of these fails closed at request time in a way indistinguishable from a
// genuine denial, so it has to stop startup instead.
func TestSecretsConfigRequirements(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(*config)
		want   string
	}{
		{"no platform", func(c *config) { c.ratlsPlatform = "" }, "--ratls-platform"},
		{"no measurements", func(c *config) { c.measurements = nil }, "--measurements"},
		{"no inventory cidrs", func(c *config) { c.inventoryCIDRs = nil }, "--sandbox-inventory-cidr"},
		{"no injected digest", func(c *config) { c.injectedComponentDigest = nil }, "--injected-component-digest"},
		{"malformed injected digest", func(c *config) { c.injectedComponentDigest = []string{"not-a-digest"} }, "--injected-component-digest"},
		{"zero max paths", func(c *config) { c.secretsMaxPaths = 0 }, "must be positive"},
		{"zero max value", func(c *config) { c.secretsMaxValueBytes = 0 }, "must be positive"},
		{"zero ledger max", func(c *config) { c.sandboxLedgerMax = 0 }, "must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := secretsConfig()
			tc.break_(&cfg)
			err := validateSecretsConfig(cfg)
			if err == nil {
				t.Fatal("expected a startup error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A handoff roll puts two CDS pods behind the Service, and the surge replica
// holds an empty store — so a workload landing on it mints a value diverging
// from the one its siblings already hold.
func TestSecretsRefusedWithHandoff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(*config)
	}{
		{"peer url", func(c *config) { c.handoffPeerURL = "https://cds.example" }},
		{"measurements", func(c *config) { c.handoffMeasurements = []string{strings.Repeat("cd", 48)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := secretsConfig()
			tc.break_(&cfg)
			err := validateSecretsConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), "handoff") {
				t.Fatalf("err = %v, want a handoff refusal", err)
			}
		})
	}
}
