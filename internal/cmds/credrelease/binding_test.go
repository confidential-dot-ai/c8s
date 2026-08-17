package credrelease

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// overrideBindingPaths points the package's sysfs/staging paths at files under
// a temp dir for the duration of the test. The files do not exist yet; each
// test writes what its scenario needs.
func overrideBindingPaths(t *testing.T) (pubPath, rtmrPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "operator-pubkey")
	rtmrPath = filepath.Join(dir, "rtmr3")
	origPub, origRTMR := operatorPubkeyPath, rtmr3SysfsPath
	operatorPubkeyPath, rtmr3SysfsPath = pubPath, rtmrPath
	t.Cleanup(func() { operatorPubkeyPath, rtmr3SysfsPath = origPub, origRTMR })
	return pubPath, rtmrPath
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// expectedRTMR3ForKey adapts runtimemeasure.ForOperatorKey for the sysfs
// fixtures the binding tests write. The formula and hardware vectors are
// pinned in pkg/runtimemeasure.
func expectedRTMR3ForKey(pub []byte) []byte {
	v := runtimemeasure.ForOperatorKey(pub)
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
// must refuse: substituted key, malformed or missing RTMR, missing/empty key.
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
// report initData (hex-encoded verbatim) as this guest's HOSTDATA.
func snpAttester(t *testing.T, initData string) string {
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
	url := snpAttester(t, hex.EncodeToString(want[:]))

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
				return snpAttester(t, hex.EncodeToString(bytes.Repeat([]byte{0}, runtimemeasure.HostDataSize)))
			},
		},
		{
			name:     "launched for a different key",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, hex.EncodeToString(otherKey[:])) },
		},
		{
			name:     "TDX-sized InitData (48-byte MRCONFIGID)",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				return snpAttester(t, hex.EncodeToString(bytes.Repeat([]byte{0xa5}, 48)))
			},
		},
		{
			name:     "InitData not hex",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, "zz") },
		},
		{
			name:     "InitData claim empty",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, "") },
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
				v.Claims.InitData = hex.EncodeToString(want[:])
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
				v.Claims.InitData = hex.EncodeToString(want[:])
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
