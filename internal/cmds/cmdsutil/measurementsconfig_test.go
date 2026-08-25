package cmdsutil

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	utilDigestA = "aa11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	utilDigestB = "bb22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	utilReg1    = "111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	utilReg2    = "222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func writeConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "measurements.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The commands that can only carry a digest list read these fields, so the
// loader must fill them or the gate would accept any attested peer.
func TestLoadMeasurementsConfigFillsFlatFields(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"a","mrtd":"00`+utilDigestA+`","rtmr":[null,"`+utilReg1+`","`+utilReg2+`"]},
		{"name":"b","mrtd":"00`+utilDigestB+`","rtmr":[null,"`+utilReg1+`","`+utilReg2+`"]}]}`)

	var digests, rtmrs []string
	set, err := LoadMeasurementsConfig(path, "--measurements-config", "--cds-measurements", "--cds-rtmrs", &digests, &rtmrs)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(set.Entries))
	}
	if len(digests) != 2 {
		t.Fatalf("digests = %v, want both images", digests)
	}
	if !slices.Contains(rtmrs, "1="+utilReg1) || !slices.Contains(rtmrs, "2="+utilReg2) {
		t.Errorf("rtmrs = %v, want the shared register pins", rtmrs)
	}
}

// Images that disagree on registers cannot share one flat set; the digests
// must still pin and the entries must keep their tuples.
func TestLoadMeasurementsConfigDropsDivergentRTMRs(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"a","mrtd":"00`+utilDigestA+`","rtmr":[null,"`+utilReg1+`"]},
		{"name":"b","mrtd":"00`+utilDigestB+`","rtmr":[null,"`+utilReg2+`"]}]}`)

	var digests, rtmrs []string
	set, err := LoadMeasurementsConfig(path, "--measurements-config", "--cds-measurements", "--cds-rtmrs", &digests, &rtmrs)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rtmrs) != 0 {
		t.Errorf("rtmrs = %v, want none: the images disagree", rtmrs)
	}
	if len(digests) != 2 {
		t.Errorf("digests = %v, want both images still pinned", digests)
	}
	for _, e := range set.Entries {
		if len(e.RTMRs) == 0 {
			t.Errorf("entry %s lost its register pins", e.Name)
		}
	}
}

func TestLoadMeasurementsConfigRejectsMixedFlags(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"00`+utilDigestA+`"}]}`)

	for _, tc := range []struct {
		name             string
		digests, rtmrs   []string
		wantFlagInErrMsg string
	}{
		{"with digests", []string{"00" + utilDigestB}, nil, "--cds-measurements"},
		{"with rtmrs", nil, []string{"1=" + utilReg1}, "--cds-rtmrs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digests, rtmrs := tc.digests, tc.rtmrs
			_, err := LoadMeasurementsConfig(path, "--measurements-config", "--cds-measurements", "--cds-rtmrs", &digests, &rtmrs)
			if err == nil {
				t.Fatal("accepted a mixed configuration")
			}
			if !strings.Contains(err.Error(), tc.wantFlagInErrMsg) {
				t.Errorf("error %q does not name %s", err, tc.wantFlagInErrMsg)
			}
		})
	}
}

func TestLoadMeasurementsConfigFailsClosed(t *testing.T) {
	var digests, rtmrs []string
	_, err := LoadMeasurementsConfig(filepath.Join(t.TempDir(), "absent.json"),
		"--measurements-config", "--cds-measurements", "--cds-rtmrs", &digests, &rtmrs)
	if err == nil {
		t.Fatal("a missing config loaded as no pinning")
	}
	if len(digests) != 0 {
		t.Errorf("digests populated from a failed load: %v", digests)
	}
}

// An unset config leaves the flat flags exactly as the operator passed them.
func TestLoadMeasurementsConfigUnsetLeavesFlagsAlone(t *testing.T) {
	digests := []string{"00" + utilDigestA}
	rtmrs := []string{"1=" + utilReg1}

	set, err := LoadMeasurementsConfig("", "--measurements-config", "--cds-measurements", "--cds-rtmrs", &digests, &rtmrs)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !set.Empty() {
		t.Error("an unset config produced reference values")
	}
	if len(digests) != 1 || len(rtmrs) != 1 {
		t.Errorf("flat flags mutated: %v / %v", digests, rtmrs)
	}
}
