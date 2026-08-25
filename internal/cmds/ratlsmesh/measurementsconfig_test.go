package ratlsmesh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	meshDigestA = "aa11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	meshDigestB = "bb22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	meshReg1    = "111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	meshReg2    = "222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func writeMeshConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "measurements.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func snpDoc(entries string) string {
	return `{"schema_version":"1","tee":"sev-snp","measurements":[` + entries + `]}`
}

func tdxDoc(entries string) string {
	return `{"schema_version":"1","tee":"tdx","measurements":[` + entries + `]}`
}

// One config fills every flat pin field: the same images serve as mesh peers
// and as CDS, so an operator passes the file once.
func TestResolveFillsPeerAndCDSFieldsFromOneFile(t *testing.T) {
	path := writeMeshConfig(t, tdxDoc(
		`{"name":"a","mrtd":"00`+meshDigestA+`","rtmr":[null,"`+meshReg1+`","`+meshReg2+`"]},`+
			`{"name":"b","mrtd":"00`+meshDigestB+`","rtmr":[null,"`+meshReg1+`","`+meshReg2+`"]}`))

	c := &proxyConfig{measurementsConfig: path}
	set, err := resolveMeasurementsConfig(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(set.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(set.Entries))
	}
	if c.measurements == "" || c.cdsMeasurements == "" {
		t.Fatalf("a pin field was left empty: peers=%q cds=%q", c.measurements, c.cdsMeasurements)
	}
	// Both roles draw on the same set, so CDS may be any listed image.
	if c.measurements != c.cdsMeasurements || c.rtmrs != c.cdsRTMRs {
		t.Errorf("roles disagree: peers=%q/%q cds=%q/%q", c.measurements, c.rtmrs, c.cdsMeasurements, c.cdsRTMRs)
	}
	if strings.Count(c.measurements, ",") != 1 {
		t.Errorf("--measurements = %q, want both digests", c.measurements)
	}
	if !strings.Contains(c.rtmrs, "1=") || !strings.Contains(c.rtmrs, "2=") {
		t.Errorf("--rtmrs = %q, want the shared register pins", c.rtmrs)
	}
	// The filled fields must parse with the same helpers run() uses.
	if _, err := ratls.ParseHexMeasurements(c.measurements); err != nil {
		t.Errorf("flat measurements do not parse: %v", err)
	}
	if _, err := ratls.ParseRTMRPinsString(c.rtmrs); err != nil {
		t.Errorf("flat rtmrs do not parse: %v", err)
	}
}

// Images that disagree on registers cannot be flattened onto one register set;
// the digests must still pin, and the tuples stay for the gates that match them.
func TestResolveDropsDivergentRTMRs(t *testing.T) {
	path := writeMeshConfig(t, tdxDoc(
		`{"name":"a","mrtd":"00`+meshDigestA+`","rtmr":[null,"`+meshReg1+`"]},`+
			`{"name":"b","mrtd":"00`+meshDigestB+`","rtmr":[null,"`+meshReg2+`"]}`))

	c := &proxyConfig{measurementsConfig: path}
	set, err := resolveMeasurementsConfig(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.rtmrs != "" || c.cdsRTMRs != "" {
		t.Errorf("register pins survived a disagreement: %q / %q", c.rtmrs, c.cdsRTMRs)
	}
	if strings.Count(c.measurements, ",") != 1 {
		t.Errorf("--measurements = %q, want both digests", c.measurements)
	}
	for _, e := range set.Entries {
		if len(e.RTMRs) == 0 {
			t.Errorf("entry %s lost its register pins", e.Name)
		}
	}
}

func TestResolveRejectsMixedFlags(t *testing.T) {
	path := writeMeshConfig(t, snpDoc(`{"name":"a","measurement":"00`+meshDigestA+`"}`))

	for _, tc := range []struct {
		name string
		cfg  proxyConfig
	}{
		{"with --measurements", proxyConfig{measurementsConfig: path, measurements: "00" + meshDigestB}},
		{"with --rtmrs", proxyConfig{measurementsConfig: path, rtmrs: "1=" + meshReg1}},
		{"with --cds-measurements", proxyConfig{measurementsConfig: path, cdsMeasurements: "00" + meshDigestB}},
		{"with --cds-rtmrs", proxyConfig{measurementsConfig: path, cdsRTMRs: "1=" + meshReg1}},
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

func TestResolveFailsClosed(t *testing.T) {
	c := &proxyConfig{measurementsConfig: filepath.Join(t.TempDir(), "absent.json")}
	if _, err := resolveMeasurementsConfig(c); err == nil {
		t.Fatal("a missing config started unpinned")
	}
	if c.measurements != "" || c.cdsMeasurements != "" {
		t.Errorf("pin fields populated from a failed load: %q / %q", c.measurements, c.cdsMeasurements)
	}
}

// --platform=auto resolves by probing the guest devices, so the config's
// platform is compared against what this node actually attests on.
func TestCheckTEEMatchesPlatform(t *testing.T) {
	snp, err := measurements.Parse([]byte(snpDoc(`{"name":"a","measurement":"00` + meshDigestA + `"}`)))
	if err != nil {
		t.Fatal(err)
	}
	tdx, err := measurements.Parse([]byte(tdxDoc(`{"name":"a","mrtd":"00` + meshDigestA + `"}`)))
	if err != nil {
		t.Fatal(err)
	}

	if err := checkTEEMatchesPlatform(snp, ratls.TEETypeSEVSNP); err != nil {
		t.Errorf("rejected an sev-snp config on an SNP node: %v", err)
	}
	if err := checkTEEMatchesPlatform(tdx, ratls.TEETypeTDX); err != nil {
		t.Errorf("rejected a tdx config on a TDX node: %v", err)
	}
	if err := checkTEEMatchesPlatform(tdx, ratls.TEETypeSEVSNP); err == nil {
		t.Error("accepted a tdx config on an SNP node")
	}
	if err := checkTEEMatchesPlatform(measurements.ReferenceValues{}, ratls.TEETypeSEVSNP); err != nil {
		t.Errorf("an unset config reported a mismatch: %v", err)
	}
}
