package getkubeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// writeLaunchData stages a launchdata dir carrying the operator key and one
// config file, and returns the dir and its expected manifest.
func writeLaunchData(t *testing.T, pub []byte) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"operator-pubkey":   pub,
		"measurements.json": []byte("{}"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := runtimemeasure.LaunchDataManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, manifest
}

// --launch-data swaps the SNP binding from the bare key to the commitment.
func TestPolicyForLaunchDataSNP(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)

	exp, err := policyFor(writeTestManifest(t, snpManifest()), pub, nil, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	if want := runtimemeasure.LaunchDataHostData(manifest); exp.hostData != want {
		t.Errorf("hostData = %x, want the launchdata commitment %x", exp.hostData, want)
	}
	if bare := runtimemeasure.HostDataForOperatorKey(pub); exp.hostData == bare {
		t.Error("hostData still the bare operator-key binding")
	}
}

// --launch-data seeds the TDX RTMR[3] chain with the commitment extend.
func TestPolicyForLaunchDataTDX(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)

	exp, err := policyFor(writeTestManifest(t, tdxManifest()), pub, nil, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	want := runtimemeasure.Extend(runtimemeasure.Zero, runtimemeasure.LaunchDataRTMR3Digest(manifest))
	if exp.rtmr3 != want {
		t.Errorf("rtmr3 = %x, want the commitment-seeded register %x", exp.rtmr3, want)
	}
}

// A key that is not the dir's operator-pubkey must be refused: the guest
// takes its key from the commitment, so a different key here could pass the
// register gate yet fail the credential exchange.
func TestPolicyForLaunchDataKeyMismatch(t *testing.T) {
	dir, _ := writeLaunchData(t, operatorPub(t))

	other := operatorPub(t)
	if _, err := policyFor(writeTestManifest(t, snpManifest()), other, nil, dir); err == nil ||
		!strings.Contains(err.Error(), "operator-pubkey is not the public half") {
		t.Fatalf("err = %v, want key mismatch refusal", err)
	}
}

func TestPolicyForLaunchDataMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "measurements.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policyFor(writeTestManifest(t, snpManifest()), operatorPub(t), nil, dir); err == nil ||
		!strings.Contains(err.Error(), "operator-pubkey") {
		t.Fatalf("err = %v, want missing operator-pubkey", err)
	}
}
