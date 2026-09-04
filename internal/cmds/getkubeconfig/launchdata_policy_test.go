package getkubeconfig

import (
	"bytes"
	"github.com/confidential-dot-ai/c8s/internal/launchdata"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
	manifest, err := launchdata.LaunchDataManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, manifest
}

// --launch-data swaps the SNP binding from the bare key to the commitment.
func TestPolicyForLaunchDataSNP(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)

	policy, err := policyFor(writeTestManifest(t, snpManifest()), pub, nil, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	exp, ok := policy.(snpMeasuredPolicy)
	if !ok {
		t.Fatalf("policy type = %T, want SNP", policy)
	}
	if want := launchdata.LaunchDataHostData(manifest); exp.hostData != want {
		t.Errorf("hostData = %x, want the launchdata commitment %x", exp.hostData, want)
	}
	if bare := runtimemeasure.HostData(pub); exp.hostData == bare {
		t.Error("hostData still the bare operator-key binding")
	}
}

// --launch-data pins the TDX MRCONFIGID to the commitment; the expected
// RTMR[3] chain seeds from Zero and carries only the workload extends.
func TestPolicyForLaunchDataTDX(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)
	dig := "sha256:" + strings.Repeat("aa", 32)

	policy, err := policyFor(writeTestManifest(t, tdxManifest()), pub, []string{dig}, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	exp := requireTDXPolicy(t, policy)
	if want := launchdata.LaunchDataMRConfigID(manifest); exp.mrconfigID != want {
		t.Errorf("mrconfigID = %x, want the launchdata commitment %x", exp.mrconfigID, want)
	}
	if want := runtimemeasure.FromDigestsSeeded(runtimemeasure.Zero, []string{dig}); exp.rtmr3 != want {
		t.Errorf("rtmr3 = %x, want the zero-seeded workload chain %x", exp.rtmr3, want)
	}
}

// Without --launch-data no MRCONFIGID is pinned, so the gate never reads the
// InitData claim on TDX.
func TestPolicyForBareKeyPinsNoMRConfigID(t *testing.T) {
	policy, err := policyFor(writeTestManifest(t, tdxManifest()), operatorPub(t), nil, "")
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	exp := requireTDXPolicy(t, policy)
	if exp.mrconfigID != [runtimemeasure.Size]byte{} {
		t.Errorf("mrconfigID = %x, want zero", exp.mrconfigID)
	}
}

// checkIdentity enforces the MRCONFIGID pin over the verified claims:
// the matching claim passes, and an absent, truncated, or different one fails
// closed.
func TestCheckIdentityMRConfigID(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)
	policy, err := policyFor(writeTestManifest(t, tdxManifest()), pub, nil, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	exp := requireTDXPolicy(t, policy)
	want := launchdata.LaunchDataMRConfigID(manifest)

	res := verifiedResultFor(exp)
	res.Claims.InitData = teetypes.HexBytes(want[:])
	if err := exp.checkIdentity(res); err != nil {
		t.Fatalf("checkIdentity: %v", err)
	}

	for name, initData := range map[string][]byte{
		"absent":    nil,
		"truncated": want[:32],
		"different": bytes.Repeat([]byte{0xa5}, 48),
	} {
		t.Run(name, func(t *testing.T) {
			res := verifiedResultFor(exp)
			res.Claims.InitData = teetypes.HexBytes(initData)
			if err := exp.checkIdentity(res); err == nil ||
				!strings.Contains(err.Error(), "MRCONFIGID") {
				t.Fatalf("err = %v, want MRCONFIGID refusal", err)
			}
		})
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
