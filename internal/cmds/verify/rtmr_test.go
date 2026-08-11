package verify

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

func sha384Hex(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 48) }

func TestParseRTMRPins(t *testing.T) {
	t.Run("indices 1 and 2 parse", func(t *testing.T) {
		got, err := parseRTMRPins([]string{"1=" + sha384Hex(0x11), "2=" + sha384Hex(0x22)})
		if err != nil {
			t.Fatalf("parseRTMRPins: %v", err)
		}
		if len(got) != 2 || hex.EncodeToString(got[1]) != sha384Hex(0x11) || hex.EncodeToString(got[2]) != sha384Hex(0x22) {
			t.Fatalf("parsed %v, want RTMR[1] and RTMR[2]", got)
		}
	})

	t.Run("no pins is nil", func(t *testing.T) {
		got, err := parseRTMRPins(nil)
		if err != nil || got != nil {
			t.Fatalf("parseRTMRPins(nil) = %v, %v; want nil, nil", got, err)
		}
	})

	// Rejected rather than ignored: accepting them would look like a pin while
	// providing none. Index 3 is NOT among them — the parser takes it and
	// resolveRTMRPins gates it on --image-manifest, because the anchor rule is
	// the opposite of RTMR[1]/[2]'s.
	for _, tc := range []struct{ name, pin, want string }{
		{"RTMR[0] tracks pod shape", "0=" + sha384Hex(0), "TD HOB"},
		{"index out of range", "9=" + sha384Hex(9), "must be 1, 2 or 3"},
		{"missing =", sha384Hex(1), "<index>=<sha384-hex>"},
		{"index not a number", "x=" + sha384Hex(1), "not a number"},
		{"value not hex", "1=zzzz", "not hex"},
		{"wrong length", "1=" + hex.EncodeToString([]byte{1, 2, 3}), "bytes, want 48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRTMRPins([]string{tc.pin})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	t.Run("repeated index rejected", func(t *testing.T) {
		_, err := parseRTMRPins([]string{"1=" + sha384Hex(1), "1=" + sha384Hex(2)})
		if err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Fatalf("error = %v, want a duplicate-index error", err)
		}
	})
}

func TestBuildPolicyCarriesRTMRPins(t *testing.T) {
	p, err := buildPolicy(config{rtmrs: []string{"2=" + sha384Hex(0x22)}})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if len(p.policy.RTMRs) != 1 || hex.EncodeToString(p.policy.RTMRs[2]) != sha384Hex(0x22) {
		t.Fatalf("policy RTMRs = %v, want RTMR[2] pinned", p.policy.RTMRs)
	}
}

// A --rtmr pin must be enforced against the verified claims, not merely
// carried on the policy. It was carried and never read: `c8s verify` verifies
// in process, and localverify.Params has no register field, so the only reader
// of VerifyPolicy.RTMRs (pkg/attestationclient) sits on a path this command
// never takes. The flag parsed, validated, and did nothing.
func TestRTMRFlagIsEnforcedNotJustCarried(t *testing.T) {
	plan, err := buildPolicy(config{rtmrs: []string{"1=" + testRTMR1, "2=" + testRTMR2}})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}

	t.Run("matching registers verify and are reported", func(t *testing.T) {
		var oc Outcome
		if !applyRTMRPins(&oc, plan.pins, tdxResult(testMRTD, matchingRTMRs())) {
			t.Fatalf("matching pins must verify, got error %q", oc.Error)
		}
		// Reported ascending, so a multi-register verdict is reproducible.
		want := []string{"1:" + testRTMR1, "2:" + testRTMR2}
		if !slices.Equal(oc.RTMRsPinned, want) {
			t.Fatalf("RTMRsPinned = %v, want %v", oc.RTMRsPinned, want)
		}
	})

	t.Run("a mismatched register fails the verdict", func(t *testing.T) {
		claims := matchingRTMRs()
		claims["rtmr_2"] = sha384Hex(0xee)
		var oc Outcome
		if applyRTMRPins(&oc, plan.pins, tdxResult(testMRTD, claims)) {
			t.Fatal("a guest whose RTMR[2] differs from the pin must not verify")
		}
		if !strings.Contains(oc.Error, "RTMR[2]") {
			t.Fatalf("error = %q, want it to name RTMR[2]", oc.Error)
		}
	})

	t.Run("an absent claim fails closed", func(t *testing.T) {
		claims := matchingRTMRs()
		delete(claims, "rtmr_1")
		var oc Outcome
		if applyRTMRPins(&oc, plan.pins, tdxResult(testMRTD, claims)) {
			t.Fatal("a pin the evidence cannot answer must fail, not pass")
		}
		if !strings.Contains(oc.Error, "carry no rtmr_1") {
			t.Fatalf("error = %q, want the absent-claim message", oc.Error)
		}
	})

	t.Run("pins.any reports the flag, so the TDX platform gate runs", func(t *testing.T) {
		if !plan.pins.any() {
			t.Fatal("rtmrPins.any() must see --rtmr, or a pin against SNP evidence is silently ignored")
		}
	})
}

// --rtmr 3= is the same pin --expected-rtmr3 gives, under the same rules, so
// there is one flag for every register. What it is NOT is interchangeable with
// --rtmr 1=/2=: registers 1 and 2 are the image, so a by-hand pin conflicts
// with a manifest, while 3 records events inside whatever image the host
// booted and therefore requires one.
func TestRTMRIndexRulesAreOpposite(t *testing.T) {
	manifest := writeTestManifest(t)

	t.Run("--rtmr 3= requires an image anchor", func(t *testing.T) {
		_, err := buildPolicy(config{rtmrs: []string{"3=" + testRTMR3}})
		if err == nil || !strings.Contains(err.Error(), "requires --image-manifest") {
			t.Fatalf("error = %v, want the image-anchor requirement", err)
		}
		if !strings.Contains(err.Error(), "--rtmr 3=") {
			t.Fatalf("error = %v, want it to name the flag that was used", err)
		}
	})

	t.Run("--rtmr 3= with a manifest is accepted and pins the register", func(t *testing.T) {
		plan, err := buildPolicy(config{imageManifest: manifest, rtmrs: []string{"3=" + testRTMR3}})
		if err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
		if hex.EncodeToString(plan.pins.rtmr3) != testRTMR3 {
			t.Fatalf("rtmr3 = %x, want it filled from --rtmr 3=", plan.pins.rtmr3)
		}
		// It lands in the RTMR[3] slot, not the by-hand set, so it is not also
		// subjected to the conflict rule that governs 1 and 2.
		if len(plan.pins.manual) != 0 {
			t.Fatalf("manual = %v, want index 3 moved to the rtmr3 slot", plan.pins.manual)
		}
	})

	t.Run("--rtmr 1= conflicts with the same manifest that 3= requires", func(t *testing.T) {
		_, err := buildPolicy(config{imageManifest: manifest, rtmrs: []string{"1=" + testRTMR1}})
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with --image-manifest") {
			t.Fatalf("error = %v, want the conflict", err)
		}
	})

	t.Run("--rtmr 3= and --expected-rtmr3 name one register twice", func(t *testing.T) {
		_, err := buildPolicy(config{
			imageManifest:    manifest,
			rtmrs:            []string{"3=" + testRTMR3},
			expectedRTMR3Hex: testRTMR3,
		})
		if err == nil || !strings.Contains(err.Error(), "name the register once") {
			t.Fatalf("error = %v, want the duplicate-source refusal", err)
		}
	})

	t.Run("the deprecated spelling still pins", func(t *testing.T) {
		plan, err := buildPolicy(config{imageManifest: manifest, expectedRTMR3Hex: testRTMR3})
		if err != nil {
			t.Fatalf("--expected-rtmr3 must keep working: %v", err)
		}
		if hex.EncodeToString(plan.pins.rtmr3) != testRTMR3 {
			t.Fatalf("rtmr3 = %x, want the deprecated flag to fill the same slot", plan.pins.rtmr3)
		}
	})
}
