package verify

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

var testPCR4 = strings.Repeat("5e", 32)

// azResult fabricates a passing az-snp verdict carrying the given vTPM PCR
// claims, the shape attestation-go's ApplyTPMClaims produces.
func azResult(launch string, pcrs map[string]any) *teetypes.VerificationResult {
	var platformData map[string]any
	if pcrs != nil {
		platformData = map[string]any{"tpm": pcrs}
	}
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformAzSNP,
		Claims: teetypes.Claims{
			LaunchDigest: launch,
			PlatformData: platformData,
		},
	}
}

func TestPCRPinVerifies(t *testing.T) {
	cfg := config{pcrs: []string{"4=" + testPCR4}}
	plan := mustPlan(t, cfg)

	oc := newOutcome(cfg, &evidence{platform: "az-snp"}, azResult(strings.Repeat("aa", 48), map[string]any{"pcr04": testPCR4}), nil, plan)
	if !oc.Verified {
		t.Fatalf("matching PCR pin must verify: %s", oc.Error)
	}
	if want := []string{"4:" + testPCR4}; len(oc.PCRsPinned) != 1 || oc.PCRsPinned[0] != want[0] {
		t.Fatalf("PCRsPinned = %v, want %v", oc.PCRsPinned, want)
	}
}

func TestPCRPinMismatchFails(t *testing.T) {
	cfg := config{pcrs: []string{"4=" + testPCR4}}
	plan := mustPlan(t, cfg)

	oc := newOutcome(cfg, &evidence{platform: "az-snp"}, azResult(strings.Repeat("aa", 48), map[string]any{"pcr04": strings.Repeat("ab", 32)}), nil, plan)
	if oc.Verified {
		t.Fatal("a mismatched PCR verified")
	}
	if !strings.Contains(oc.Error, "PCR[4]") {
		t.Errorf("error = %q, want the PCR[4] mismatch named", oc.Error)
	}
}

func TestPCRPinUnreportedFails(t *testing.T) {
	cfg := config{pcrs: []string{"4=" + testPCR4}}
	plan := mustPlan(t, cfg)

	oc := newOutcome(cfg, &evidence{platform: "az-snp"}, azResult(strings.Repeat("aa", 48), nil), nil, plan)
	if oc.Verified {
		t.Fatal("a pinned but unreported PCR verified")
	}
	if !strings.Contains(oc.Error, "tpm.pcr04") {
		t.Errorf("error = %q, want the missing tpm.pcr04 claim named", oc.Error)
	}
}

// A --pcr pin against evidence with no vTPM is an inapplicable policy, never
// an ignored option — same rule as the RTMR pins on non-TDX evidence.
func TestPCRPinAgainstNonAzEvidenceIsAPolicyError(t *testing.T) {
	cfg := config{pcrs: []string{"4=" + testPCR4}}
	plan := mustPlan(t, cfg)

	oc := newOutcome(cfg, &evidence{platform: "snp"}, &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: strings.Repeat("aa", 48)},
	}, nil, plan)
	if oc.Verified {
		t.Fatal("a --pcr pin against SNP evidence verified")
	}
	if !strings.Contains(oc.Error, "--pcr") {
		t.Errorf("error = %q, want the inapplicable --pcr pin named", oc.Error)
	}
}

func TestPCRPinFlagParsing(t *testing.T) {
	if _, err := buildPolicy(config{pcrs: []string{"24=" + testPCR4}}); err == nil {
		t.Fatal("PCR index 24 accepted; the vTPM has 24 registers, 0-23")
	}
	if _, err := buildPolicy(config{pcrs: []string{"4=abcd"}}); err == nil {
		t.Fatal("a short PCR value was accepted")
	}
}
