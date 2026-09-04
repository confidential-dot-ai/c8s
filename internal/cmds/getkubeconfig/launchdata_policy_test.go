package getkubeconfig

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"

	"github.com/confidential-dot-ai/c8s/internal/launchdata"
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

// --launch-data swaps the SNP binding from the bare key to the commitment:
// HOSTDATA must carry SHA-256(manifest), and the key binding no longer passes.
func TestPolicyForLaunchDataSNP(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)

	exp, err := policyFor(writeTestManifest(t, snpManifest()), pub, nil, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	if !bytes.Equal(exp.launchData, manifest) {
		t.Fatalf("launchData = %q, want the bundle manifest %q", exp.launchData, manifest)
	}

	res := snpResultFor(t, exp, 2)
	if want := launchdata.LaunchDataHostData(manifest); !bytes.Equal(res.Claims.InitData, want[:]) {
		t.Fatalf("expected HOSTDATA = %x, want the launchdata commitment %x", res.Claims.InitData, want)
	}
	if err := exp.checkIdentity(res); err != nil {
		t.Fatalf("checkIdentity: %v", err)
	}

	bare := runtimemeasure.HostData(pub)
	res.Claims.InitData = teetypes.HexBytes(bare[:])
	if err := exp.checkIdentity(res); err == nil {
		t.Error("the bare operator-key binding still satisfies the launchdata gate")
	}
}

// --launch-data pins the TDX MRCONFIGID to the commitment; the expected
// RTMR[3] chain seeds from Zero and carries only the workload extends.
func TestPolicyForLaunchDataTDX(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)
	dig := "sha256:" + strings.Repeat("aa", 32)

	exp, err := policyFor(writeTestManifest(t, tdxManifest()), pub, []string{dig}, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	res := verifiedResultFor(exp)
	if want := launchdata.LaunchDataMRConfigID(manifest); !bytes.Equal(res.Claims.InitData, want[:]) {
		t.Fatalf("expected MRCONFIGID = %x, want the launchdata commitment %x", res.Claims.InitData, want)
	}
	if want := runtimemeasure.FromDigestsSeeded(runtimemeasure.Zero, []string{dig}); !bytes.Equal(expectedRTMR3(exp), want[:]) {
		t.Fatalf("expected RTMR[3] = %x, want the zero-seeded workload chain %x", expectedRTMR3(exp), want)
	}
	if err := exp.checkIdentity(res); err != nil {
		t.Fatalf("checkIdentity: %v", err)
	}

	// The operator-key seed is what the gate would demand without the bundle,
	// so a node still seeding RTMR[3] from it must be refused.
	seeded := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pub), []string{dig})
	res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seeded[:])
	if err := exp.checkIdentity(res); err == nil || !strings.Contains(err.Error(), "RTMR[3]") {
		t.Fatalf("err = %v, want an RTMR[3] refusal", err)
	}
}

// Without --launch-data the gate pins no commitment, so the TDX arm never
// reads the InitData claim and the operator-key seed still binds RTMR[3].
func TestPolicyForBareKeyPinsNoMRConfigID(t *testing.T) {
	pub := operatorPub(t)
	exp, err := policyFor(writeTestManifest(t, tdxManifest()), pub, nil, "")
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	if exp.launchData != nil {
		t.Fatalf("launchData = %q, want none", exp.launchData)
	}
	res := verifiedResultFor(exp)
	res.Claims.InitData = teetypes.HexBytes(bytes.Repeat([]byte{0xa5}, runtimemeasure.Size))
	if err := exp.checkIdentity(res); err != nil {
		t.Fatalf("checkIdentity: %v", err)
	}
}

// checkIdentity enforces the MRCONFIGID pin over the verified claims: the
// matching claim passes, and an absent, truncated, or different one fails
// closed.
func TestCheckIdentityMRConfigID(t *testing.T) {
	pub := operatorPub(t)
	dir, manifest := writeLaunchData(t, pub)
	exp, err := policyFor(writeTestManifest(t, tdxManifest()), pub, nil, dir)
	if err != nil {
		t.Fatalf("policyFor: %v", err)
	}
	want := launchdata.LaunchDataMRConfigID(manifest)

	for name, initData := range map[string][]byte{
		"absent":    nil,
		"truncated": want[:32],
		"different": bytes.Repeat([]byte{0xa5}, runtimemeasure.Size),
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
