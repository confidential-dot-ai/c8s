package credrelease

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// writeLaunchDataDir stages a bundle dir (operator key + one config file) and
// returns the dir and its manifest.
func writeLaunchDataDir(t *testing.T, pub []byte) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "operator-pubkey"), pub)
	writeFileT(t, filepath.Join(dir, "measurements.json"), []byte("{}"))
	manifest, err := runtimemeasure.LaunchDataManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, manifest
}

// The TDX launchdata arm releases the bundled key when RTMR[3] carries the
// bundle commitment, and refuses any other register value.
func TestLoadMeasuredOperatorKeyLaunchDataTDX(t *testing.T) {
	_, rtmrPath := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	dir, manifest := writeLaunchDataDir(t, pub)
	want := runtimemeasure.Extend(runtimemeasure.Zero, runtimemeasure.LaunchDataRTMR3Digest(manifest))
	writeFileT(t, rtmrPath, want[:])

	got, err := LoadMeasuredOperatorKey(context.Background(), "tdx", "", dir)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}

	// A post-boot edit of any staged file changes the recomputed commitment.
	writeFileT(t, filepath.Join(dir, "measurements.json"), []byte("{\"tampered\":1}"))
	if _, err := LoadMeasuredOperatorKey(context.Background(), "tdx", "", dir); err == nil ||
		!strings.Contains(err.Error(), "measured RTMR[3]") {
		t.Fatalf("err = %v, want RTMR[3] mismatch", err)
	}
}

// The SNP launchdata arm compares the recomputed commitment against the
// verified self-report's HOSTDATA.
func TestLoadMeasuredOperatorKeyLaunchDataSNP(t *testing.T) {
	overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	dir, manifest := writeLaunchDataDir(t, pub)
	want := runtimemeasure.LaunchDataHostData(manifest)

	got, err := LoadMeasuredOperatorKey(context.Background(), "sev-snp", snpAttester(t, want[:]), dir)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}

	bare := runtimemeasure.HostDataForOperatorKey(pub)
	if _, err := LoadMeasuredOperatorKey(context.Background(), "sev-snp", snpAttester(t, bare[:]), dir); err == nil ||
		!strings.Contains(err.Error(), "launch-committed HOSTDATA") {
		t.Fatalf("err = %v, want HOSTDATA mismatch (bare key binding must not satisfy the bundle arm)", err)
	}
}

// An absent bundle dir falls back to the opkeydata single-key flow.
func TestLoadMeasuredOperatorKeyLaunchDataAbsentDirFallsBack(t *testing.T) {
	pubPath, rtmrPath := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)
	writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))

	got, err := LoadMeasuredOperatorKey(context.Background(), "tdx", "",
		filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}
}

// A bundle without an operator key is refused, not silently fallen back from.
func TestLoadMeasuredOperatorKeyLaunchDataMissingKey(t *testing.T) {
	overrideBindingPaths(t)
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "measurements.json"), []byte("{}"))
	if _, err := LoadMeasuredOperatorKey(context.Background(), "tdx", "", dir); err == nil ||
		!strings.Contains(err.Error(), "operator-pubkey") {
		t.Fatalf("err = %v, want missing bundled key", err)
	}
}
