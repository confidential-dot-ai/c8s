package verify

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

var (
	testMRTD  = strings.Repeat("1a", 48)
	testRTMR1 = strings.Repeat("2b", 48)
	testRTMR2 = strings.Repeat("3c", 48)
	testRTMR3 = strings.Repeat("4d", 48)
)

func writeTestManifest(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	content := `{"mrtd":"` + testMRTD + `","rtmr1":"` + testRTMR1 + `","rtmr2":"` + testRTMR2 + `"}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tdxResult fabricates a passing TDX verdict carrying the given launch digest
// and rtmr_N claims, the shape attestation-go extracts from a verified quote.
func tdxResult(launch string, rtmrs map[string]any) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformTDX,
		Claims: teetypes.Claims{
			LaunchDigest: launch,
			PlatformData: rtmrs,
		},
	}
}

func matchingRTMRs() map[string]any {
	return map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": testRTMR3}
}

// The manifest is one atomic pin: MRTD joins the measurement allowlist and
// RTMR[1]/[2] compare exactly, so a full match verifies and reports what was
// enforced.
func TestImageManifestPinVerifies(t *testing.T) {
	cfg := config{imageManifest: writeTestManifest(t), expectedRTMR3Hex: testRTMR3}
	policy, err := buildPolicy(cfg)
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if len(policy.Measurements) != 1 || hex.EncodeToString(policy.Measurements[0]) != testMRTD {
		t.Fatalf("manifest MRTD must join the measurement allowlist, got %d entries", len(policy.Measurements))
	}

	oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, matchingRTMRs()), nil, policy)
	if !oc.Verified {
		t.Fatalf("full tuple match must verify: %s", oc.Error)
	}
	want := []string{"1:" + testRTMR1, "2:" + testRTMR2, "3:" + testRTMR3}
	if len(oc.RTMRsPinned) != len(want) {
		t.Fatalf("RTMRsPinned = %v, want %v", oc.RTMRsPinned, want)
	}
	for i := range want {
		if oc.RTMRsPinned[i] != want[i] {
			t.Errorf("RTMRsPinned[%d] = %q, want %q", i, oc.RTMRsPinned[i], want[i])
		}
	}
	if len(oc.Warnings) != 0 {
		t.Errorf("a full image pin must not warn: %v", oc.Warnings)
	}
}

func TestRTMRPinMismatchesFailClosed(t *testing.T) {
	manifest := writeTestManifest(t)
	for _, tc := range []struct {
		name    string
		cfg     config
		rtmrs   map[string]any
		wantErr string
	}{
		{"wrong rtmr1", config{imageManifest: manifest},
			map[string]any{"rtmr_1": strings.Repeat("00", 48), "rtmr_2": testRTMR2},
			"RTMR[1] (guest kernel)"},
		{"wrong rtmr2", config{imageManifest: manifest},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": strings.Repeat("00", 48)},
			"RTMR[2] (guest rootfs)"},
		{"wrong rtmr3", config{expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_3": strings.Repeat("00", 48)},
			"RTMR[3]"},
		{"absent rtmr1 claim", config{imageManifest: manifest},
			map[string]any{"rtmr_2": testRTMR2},
			"carry no rtmr_1"},
		{"absent rtmr3 claim", config{expectedRTMR3Hex: testRTMR3},
			map[string]any{},
			"carry no rtmr_3"},
		{"malformed claim", config{expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_3": "zz"},
			"malformed"},
		{"claim wrong length", config{expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_3": "abcd"},
			"malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := buildPolicy(tc.cfg)
			if err != nil {
				t.Fatalf("buildPolicy: %v", err)
			}
			oc := newOutcome(tc.cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, tc.rtmrs), nil, policy)
			if oc.Verified {
				t.Fatal("mismatched/absent RTMR claim must fail the verdict")
			}
			if !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", oc.Error, tc.wantErr)
			}
		})
	}
}

// An RTMR pin against non-TDX evidence is a policy error naming the platform,
// never a silently ignored option: SNP has no runtime measurement registers,
// so "pass" would mean "nothing enforced".
func TestRTMRPinRejectsNonTDXPlatform(t *testing.T) {
	snpLaunch := strings.Repeat("ab", 48)
	for _, cfg := range []config{
		{imageManifest: writeTestManifest(t), measurements: []string{snpLaunch}},
		{expectedRTMR3Hex: testRTMR3, measurements: []string{snpLaunch}},
	} {
		policy, err := buildPolicy(cfg)
		if err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims:         teetypes.Claims{LaunchDigest: snpLaunch},
		}
		oc := newOutcome(cfg, &evidence{platform: "snp"}, result, nil, policy)
		if oc.Verified {
			t.Fatal("an RTMR pin with SNP evidence must be a hard verdict failure")
		}
		if !strings.Contains(oc.Error, `"snp"`) || !strings.Contains(oc.Error, "TDX") {
			t.Errorf("error = %q, want it to name the platform and the TDX-only rule", oc.Error)
		}
	}
}

// A passing TDX verdict pinned on MRTD alone must warn prominently: MRTD
// covers only the TDVF firmware, and the guest kernel/rootfs stay unmeasured
// by that policy.
func TestTDXMRTDOnlyWarns(t *testing.T) {
	cfg := config{measurements: []string{testMRTD}}
	policy, err := buildPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, matchingRTMRs()), nil, policy)
	if !oc.Verified {
		t.Fatalf("verdict failed: %s", oc.Error)
	}
	if len(oc.Warnings) != 1 || !strings.Contains(oc.Warnings[0], "UNMEASURED") {
		t.Fatalf("Warnings = %v, want the MRTD-only warning", oc.Warnings)
	}

	// And the text render surfaces it.
	var out strings.Builder
	renderText(cfg, oc, &out)
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), "MRTD") {
		t.Errorf("text render must carry the MRTD-only warning:\n%s", out.String())
	}

	// No warning for the same policy against SNP: MRTD is a TDX concept.
	snpResult := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: testMRTD},
	}
	snpOC := newOutcome(cfg, &evidence{platform: "snp"}, snpResult, nil, policy)
	if !snpOC.Verified || len(snpOC.Warnings) != 0 {
		t.Errorf("SNP verdict must not carry the TDX warning: verified=%v warnings=%v", snpOC.Verified, snpOC.Warnings)
	}
}

func TestRTMRPinFlagErrors(t *testing.T) {
	badManifest := filepath.Join(t.TempDir(), "artifacts.json")
	if err := os.WriteFile(badManifest, []byte(`{"files":{"disk.img":"sha256:ab"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{"rtmr3 not hex", config{expectedRTMR3Hex: strings.Repeat("zz", 48)}, "not hex"},
		{"rtmr3 too short", config{expectedRTMR3Hex: "abcd"}, "want 48"},
		{"rtmr3 too long", config{expectedRTMR3Hex: strings.Repeat("ab", 64)}, "want 48"},
		{"manifest missing", config{imageManifest: filepath.Join(t.TempDir(), "absent.json")}, "read image manifest"},
		{"generic artifact-hash manifest", config{imageManifest: badManifest}, "not it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildPolicy(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("buildPolicy error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
