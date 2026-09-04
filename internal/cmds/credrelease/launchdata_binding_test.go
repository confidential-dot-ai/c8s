package credrelease

import (
	"context"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/launchdata"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// writeLaunchDataDir stages a bundle dir (operator key + one config file) and
// returns the dir and its manifest.
func writeLaunchDataDir(t *testing.T, pub []byte) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "operator-pubkey"), pub)
	writeFileT(t, filepath.Join(dir, "measurements.json"), []byte("{}"))
	manifest, err := launchdata.LaunchDataManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, manifest
}

// The TDX launchdata arm releases the bundled key when the guest's MRCONFIGID
// carries the bundle commitment, and refuses any other value.
func TestLoadMeasuredOperatorKeyLaunchDataTDX(t *testing.T) {
	pub := []byte("operator public key bytes")
	dir, manifest := writeLaunchDataDir(t, pub)
	want := launchdata.LaunchDataMRConfigID(manifest)
	url := launchDataAttester(t, teetypes.PlatformTDX, want[:])

	got, err := LoadMeasuredOperatorKey(context.Background(), url, dir)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}

	// A post-boot edit of any staged file changes the recomputed commitment.
	writeFileT(t, filepath.Join(dir, "measurements.json"), []byte("{\"tampered\":1}"))
	if _, err := LoadMeasuredOperatorKey(context.Background(), url, dir); err == nil ||
		!strings.Contains(err.Error(), "launch-committed MRCONFIGID") {
		t.Fatalf("err = %v, want MRCONFIGID mismatch", err)
	}
}

// The SNP launchdata arm compares the recomputed commitment against the
// verified self-report's HOSTDATA.
func TestLoadMeasuredOperatorKeyLaunchDataSNP(t *testing.T) {
	pub := []byte("operator public key bytes")
	dir, manifest := writeLaunchDataDir(t, pub)
	want := launchdata.LaunchDataHostData(manifest)

	got, err := LoadMeasuredOperatorKey(context.Background(), launchDataAttester(t, teetypes.PlatformSNP, want[:]), dir)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}

	bare := runtimemeasure.HostData(pub)
	if _, err := LoadMeasuredOperatorKey(context.Background(), launchDataAttester(t, teetypes.PlatformSNP, bare[:]), dir); err == nil ||
		!strings.Contains(err.Error(), "launch-committed HOSTDATA") {
		t.Fatalf("err = %v, want HOSTDATA mismatch (bare key binding must not satisfy the bundle arm)", err)
	}
}

// An absent bundle dir falls back to the opkeydata single-key flow.
func TestLoadMeasuredOperatorKeyLaunchDataAbsentDirFallsBack(t *testing.T) {
	pub := []byte("operator public key bytes")
	stageOperatorPubkey(t, pub)
	url := attester(t, teetypes.PlatformTDX, tdxBinding(pub))

	got, err := LoadMeasuredOperatorKey(context.Background(), url,
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
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "measurements.json"), []byte("{}"))
	if _, err := LoadMeasuredOperatorKey(context.Background(), "", dir); err == nil ||
		!strings.Contains(err.Error(), "operator-pubkey") {
		t.Fatalf("err = %v, want missing bundled key", err)
	}
}

// launchDataAttester supplies the launch commitment in the verified InitData claim.
func launchDataAttester(t *testing.T, platform teetypes.PlatformType, binding []byte) string {
	t.Helper()
	stub := testattest.New(t)
	stub.SetPlatform(types.Platform(platform))
	v := testattest.PassingVerdict("")
	v.Claims.InitData = binding
	stub.SetVerdict(v)
	return stub.URL
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
