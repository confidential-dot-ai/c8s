package credrelease

import (
	"os"
	"path/filepath"
	"testing"

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

	got, err := LoadMeasuredOperatorKey()
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
			if _, err := LoadMeasuredOperatorKey(); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
