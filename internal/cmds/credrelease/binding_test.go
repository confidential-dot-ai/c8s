package credrelease

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/tdxrtmr"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// overrideBindingPaths points the staging path and the RTMR sysfs root at a
// temp dir for the duration of the test. The files do not exist yet; each
// test writes what its scenario needs.
func overrideBindingPaths(t *testing.T) (pubPath, rtmrPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "operator-pubkey")
	origPub, origRoot := operatorPubkeyPath, tdxrtmr.SysfsRoot
	operatorPubkeyPath, tdxrtmr.SysfsRoot = pubPath, dir
	t.Cleanup(func() { operatorPubkeyPath, tdxrtmr.SysfsRoot = origPub, origRoot })
	return pubPath, tdxrtmr.Path(3)
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// expectedRTMR3ForKey is the register a dynamic operator-key boot leaves for
// the sysfs fixtures the binding tests write: the seed extended by the
// dynamic mode event. The formula and vectors are pinned in
// pkg/runtimemeasure.
func expectedRTMR3ForKey(pub []byte) []byte {
	v := runtimemeasure.ForDynamic(runtimemeasure.ForOperatorKey(pub))
	return v[:]
}

// TestLoadMeasuredOperatorKey covers the happy path: the staged pubkey matches
// the (fake) RTMR[3] the initrd would have extended, so the key is released.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	pubPath, rtmrPath := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)
	writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))

	got, err := LoadMeasuredOperatorKey(context.Background(), "tdx", "")
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}
}

// TestLoadMeasuredOperatorKeyFailsClosed enumerates the ways the anchor check
// must refuse: substituted key, a register without the mode event or with
// the wrong one, malformed or missing RTMR, missing/empty key.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	pub := []byte("operator public key bytes")
	tests := []struct {
		name  string
		stage func(t *testing.T, pubPath, rtmrPath string)
	}{
		{
			name: "substituted pubkey",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, []byte("a different key the host swapped in"))
				writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))
			},
		},
		{
			name: "bare seed: mode event not extended",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
				seed := runtimemeasure.ForOperatorKey(pub)
				writeFileT(t, rtmrPath, seed[:])
			},
		},
		{
			name: "static mode event on an operator-key boot",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
				reg := runtimemeasure.Extend(runtimemeasure.ForOperatorKey(pub), runtimemeasure.ModeStatic)
				writeFileT(t, rtmrPath, reg[:])
			},
		},
		{
			name: "keyless dynamic register",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
				reg := runtimemeasure.ForDynamic(runtimemeasure.Zero)
				writeFileT(t, rtmrPath, reg[:])
			},
		},
		{
			name: "rtmr wrong length",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
				writeFileT(t, rtmrPath, make([]byte, 47))
			},
		},
		{
			name: "rtmr missing",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
			},
		},
		{
			name:  "pubkey missing",
			stage: func(t *testing.T, pubPath, rtmrPath string) {},
		},
		{
			name: "pubkey empty",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, nil)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubPath, rtmrPath := overrideBindingPaths(t)
			tc.stage(t, pubPath, rtmrPath)
			if _, err := LoadMeasuredOperatorKey(context.Background(), "tdx", ""); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// snpAttester returns the URL of a stub attestation-api whose verified claims
// report initData verbatim as this guest's HOSTDATA.
func snpAttester(t *testing.T, initData []byte) string {
	t.Helper()
	stub := testattest.New(t)
	v := testattest.PassingVerdict("")
	v.Claims.InitData = initData
	stub.SetVerdict(v)
	return stub.URL
}

// TestLoadMeasuredOperatorKeySNP covers the SNP happy path: the verified
// self-report's HOSTDATA equals sha256 of the staged pubkey bytes.
func TestLoadMeasuredOperatorKeySNP(t *testing.T) {
	pubPath, _ := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)
	want := runtimemeasure.HostDataForOperatorKey(pub)
	url := snpAttester(t, want[:])

	got, err := LoadMeasuredOperatorKey(context.Background(), "sev-snp", url)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}
}

// TestLoadMeasuredOperatorKeySNPFailsClosed enumerates the SNP refusals:
// keyless launch (zero HOSTDATA), a different key's HOSTDATA, TDX-shaped and
// malformed claims, an unreachable attestation-api, an unknown platform.
func TestLoadMeasuredOperatorKeySNPFailsClosed(t *testing.T) {
	pub := []byte("operator public key bytes")
	otherKey := runtimemeasure.HostDataForOperatorKey([]byte("a different operator key"))
	tests := []struct {
		name     string
		platform string
		url      func(t *testing.T) string
	}{
		{
			name:     "keyless launch: zero HOSTDATA",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				return snpAttester(t, bytes.Repeat([]byte{0}, runtimemeasure.HostDataSize))
			},
		},
		{
			name:     "launched for a different key",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, otherKey[:]) },
		},
		{
			name:     "TDX-sized InitData (48-byte MRCONFIGID)",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				return snpAttester(t, bytes.Repeat([]byte{0xa5}, 48))
			},
		},
		{
			// The wire's not-hex shape is refused by the HexBytes decoder in
			// the client; through the typed stub only widths are expressible.
			name:     "InitData wrong width",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, []byte("zz")) },
		},
		{
			name:     "InitData claim empty",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, nil) },
		},
		// The two verdict cases carry a MATCHING InitData: refusal must come
		// from verdict enforcement, not the claims compare, so a refactor
		// that drops VerifyEvidence's enforcement fails here.
		{
			name:     "verifier refuses: signature invalid",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				want := runtimemeasure.HostDataForOperatorKey(pub)
				stub := testattest.New(t)
				v := testattest.PassingVerdict("")
				v.SignatureValid = false
				v.Claims.InitData = want[:]
				stub.SetVerdict(v)
				return stub.URL
			},
		},
		{
			name:     "verifier refuses: REPORTDATA not bound",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				want := runtimemeasure.HostDataForOperatorKey(pub)
				stub := testattest.New(t)
				v := testattest.PassingVerdict("")
				v.ReportDataMatch = nil
				v.Claims.InitData = want[:]
				stub.SetVerdict(v)
				return stub.URL
			},
		},
		{
			name:     "attestation-api unreachable",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return "http://127.0.0.1:1" },
		},
		{
			name:     "unknown platform has no binding check",
			platform: "no-such-platform",
			url:      func(t *testing.T) string { return "" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubPath, _ := overrideBindingPaths(t)
			writeFileT(t, pubPath, pub)
			if _, err := LoadMeasuredOperatorKey(context.Background(), tc.platform, tc.url(t)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
