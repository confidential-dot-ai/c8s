package cds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "measurements.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	cfgDigestA = "aa11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	cfgDigestB = "bb22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	cfgReg1    = "111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	cfgReg2    = "222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

// The gates that can only read the flat list must still see a pin, or a
// config-mode start would silently unpin /sign-csr, /secrets and handoff.
func TestResolveMeasurementsConfigFillsFlatLists(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[
		{"name":"a","measurement":"00`+cfgDigestA+`"},
		{"name":"b","measurement":"00`+cfgDigestB+`"}]}`)

	cfg := config{measurementsConfig: path}
	set, err := resolveMeasurementsConfig(&cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(set.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(set.Entries))
	}
	if len(cfg.measurements) != 2 {
		t.Fatalf("flat measurements = %v, want 2 digests", cfg.measurements)
	}
	if refs := parseReferenceDigests(cfg.measurements); len(refs) != 2 {
		t.Errorf("reference digests = %v, want both images", refs)
	}
}

// RTMR pins shared by every image can be carried by the flat list; the gates
// that take one register set then keep enforcing them.
func TestResolveMeasurementsConfigCarriesCommonRTMRs(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"a","mrtd":"00`+cfgDigestA+`","rtmr":[null,"`+cfgReg1+`","`+cfgReg2+`"]},
		{"name":"b","mrtd":"00`+cfgDigestB+`","rtmr":[null,"`+cfgReg1+`","`+cfgReg2+`"]}]}`)

	cfg := config{measurementsConfig: path}
	if _, err := resolveMeasurementsConfig(&cfg); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(cfg.rtmrs) != 2 {
		t.Fatalf("flat rtmrs = %v, want 2 pins", cfg.rtmrs)
	}
	for _, want := range []string{"1=" + cfgReg1, "2=" + cfgReg2} {
		if !containsPin(cfg.rtmrs, want) {
			t.Errorf("rtmrs %v missing %s", cfg.rtmrs, want)
		}
	}
}

// Images with different registers cannot be flattened onto one register set.
// The digests must still pin, and the tuples stay available for /attest.
func TestResolveMeasurementsConfigDropsDivergentRTMRs(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"a","mrtd":"00`+cfgDigestA+`","rtmr":[null,"`+cfgReg1+`"]},
		{"name":"b","mrtd":"00`+cfgDigestB+`","rtmr":[null,"`+cfgReg2+`"]}]}`)

	cfg := config{measurementsConfig: path}
	set, err := resolveMeasurementsConfig(&cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(cfg.rtmrs) != 0 {
		t.Errorf("flat rtmrs = %v, want none: the images disagree", cfg.rtmrs)
	}
	if len(cfg.measurements) != 2 {
		t.Errorf("flat measurements = %v, want both digests", cfg.measurements)
	}
	for _, e := range set.Entries {
		if len(e.RTMRs) == 0 {
			t.Errorf("entry %s lost its register pins", e.Name)
		}
	}
}

func TestResolveMeasurementsConfigRejectsMixedFlags(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"00`+cfgDigestA+`"}]}`)

	for _, tc := range []struct {
		name string
		cfg  config
	}{
		{"with --measurements", config{measurementsConfig: path, measurements: []string{"00" + cfgDigestB}}},
		{"with --rtmrs", config{measurementsConfig: path, rtmrs: []string{"1=" + cfgReg1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveMeasurementsConfig(&tc.cfg)
			if err == nil {
				t.Fatal("accepted a mixed configuration")
			}
			if !strings.Contains(err.Error(), "cannot be combined") {
				t.Errorf("error %q does not explain the conflict", err)
			}
		})
	}
}

// A config for the other platform refuses every peer at runtime, so it has to
// stop startup instead.
func TestResolveMeasurementsConfigRejectsPlatformMismatch(t *testing.T) {
	path := writeConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[{"name":"a","mrtd":"00`+cfgDigestA+`"}]}`)

	cfg := config{measurementsConfig: path, ratlsPlatform: "sev-snp"}
	_, err := resolveMeasurementsConfig(&cfg)
	if err == nil {
		t.Fatal("accepted tdx reference values on an sev-snp platform")
	}
	for _, want := range []string{"tdx", "sev-snp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if len(cfg.measurements) != 0 {
		t.Errorf("flat measurements populated despite the mismatch: %v", cfg.measurements)
	}
}

// The aliases the platform flag accepts must compare equal to the spelling the
// document uses.
func TestResolveMeasurementsConfigAcceptsPlatformAliases(t *testing.T) {
	snp := writeConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"00`+cfgDigestA+`"}]}`)
	tdx := writeConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[{"name":"a","mrtd":"00`+cfgDigestA+`"}]}`)

	for _, tc := range []struct{ platform, path string }{
		{"snp", snp}, {"az-snp", snp}, {"gcp-snp", snp}, {"sev-snp", snp},
		{"tdx", tdx}, {"az-tdx", tdx}, {"gcp-tdx", tdx},
		{"", snp}, // validateConfig reports a missing platform, not this check
	} {
		t.Run(tc.platform, func(t *testing.T) {
			cfg := config{measurementsConfig: tc.path, ratlsPlatform: tc.platform}
			if _, err := resolveMeasurementsConfig(&cfg); err != nil {
				t.Fatalf("rejected platform %q: %v", tc.platform, err)
			}
		})
	}
}

// A named config that cannot be read must stop startup, never degrade to no
// pinning.
func TestResolveMeasurementsConfigFailsClosed(t *testing.T) {
	cfg := config{measurementsConfig: filepath.Join(t.TempDir(), "absent.json")}
	if _, err := resolveMeasurementsConfig(&cfg); err == nil {
		t.Fatal("a missing config started unpinned")
	}
	if len(cfg.measurements) != 0 {
		t.Errorf("flat measurements populated from a failed load: %v", cfg.measurements)
	}
}

func containsPin(pins []string, want string) bool {
	for _, p := range pins {
		if p == want {
			return true
		}
	}
	return false
}
