package credrelease

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var operatorPub = []byte("operator public key bytes")

// stageOperatorPubkey points the package's staging path at a temp file and
// writes pub to it. Pass nil to leave the file absent.
func stageOperatorPubkey(t *testing.T, pub []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-pubkey")
	orig := operatorPubkeyPath
	operatorPubkeyPath = path
	t.Cleanup(func() { operatorPubkeyPath = orig })
	if pub == nil {
		return
	}
	if err := os.WriteFile(path, pub, 0o600); err != nil {
		t.Fatal(err)
	}
}

// attester serves a fake attestation-api whose verified self-report carries
// binding in whichever claim the platform uses: RTMR[3] on TDX, HOSTDATA on
// SEV-SNP. Both arms go through one code path now, so both are exercised by
// varying only the platform and the claim.
func attester(t *testing.T, platform teetypes.PlatformType, binding []byte) string {
	t.Helper()
	stub := testattest.New(t)
	stub.SetPlatform(types.Platform(platform))
	v := testattest.PassingVerdict("")
	if platform.IsTDX() {
		v.Claims.PlatformData = map[string]any{"rtmr_3": hex.EncodeToString(binding)}
	} else {
		v.Claims.InitData = binding
	}
	stub.SetVerdict(v)
	return stub.URL
}

func tdxBinding(pub []byte) []byte { v := runtimemeasure.Seed(pub); return v[:] }
func snpBinding(pub []byte) []byte { v := runtimemeasure.HostData(pub); return v[:] }

// The happy path on both platforms: the staged pubkey is the one the launch
// bound, so the key is released. The caller no longer passes a platform — it
// comes from the verified report.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		binding  []byte
	}{
		{teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{teetypes.PlatformAzTDX, tdxBinding(operatorPub)},
		{teetypes.PlatformSNP, snpBinding(operatorPub)},
		{teetypes.PlatformGcpSNP, snpBinding(operatorPub)},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			url := attester(t, tc.platform, tc.binding)

			got, err := LoadMeasuredOperatorKey(context.Background(), url, "")
			if err != nil {
				t.Fatalf("LoadMeasuredOperatorKey: %v", err)
			}
			if string(got) != string(operatorPub) {
				t.Errorf("returned key = %q, want %q", got, operatorPub)
			}
		})
	}
}

// Every way the anchor check can fail must refuse. Releasing a key the launch
// did not bind is the vulnerability this check exists to prevent.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	otherKey := []byte("a different operator key")
	zeroTDX := make([]byte, runtimemeasure.Size)
	zeroSNP := make([]byte, runtimemeasure.HostDataSize)

	for _, tc := range []struct {
		name     string
		staged   []byte
		platform teetypes.PlatformType
		binding  []byte
	}{
		{"no staged pubkey", nil, teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{"empty staged pubkey", []byte{}, teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{"tdx: register holds another key's seed", operatorPub, teetypes.PlatformTDX, tdxBinding(otherKey)},
		{"tdx: keyless launch leaves the register zero", operatorPub, teetypes.PlatformTDX, zeroTDX},
		{"snp: HOSTDATA holds another key", operatorPub, teetypes.PlatformSNP, snpBinding(otherKey)},
		{"snp: keyless launch leaves HOSTDATA zero", operatorPub, teetypes.PlatformSNP, zeroSNP},
		// A TDX-width value in the SNP claim is MRCONFIGID, not HOSTDATA. It
		// must be refused by width, never truncated into a match.
		{"snp claim carrying a 48-byte value", operatorPub, teetypes.PlatformSNP, tdxBinding(operatorPub)},
		{"tdx claim carrying a 32-byte value", operatorPub, teetypes.PlatformTDX, snpBinding(operatorPub)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, tc.staged)
			url := attester(t, tc.platform, tc.binding)
			if _, err := LoadMeasuredOperatorKey(context.Background(), url, ""); err == nil {
				t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
			}
		})
	}
}

// An unreachable attestation-api is a refusal, not a fallback to the local
// register: the binding must come from a report whose signature was checked.
func TestLoadMeasuredOperatorKeyRefusesUnreachableAttester(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	if _, err := LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1", ""); err == nil {
		t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
	}
}

// A platform this build has no binding rules for gets no key.
func TestLoadMeasuredOperatorKeyRefusesUnknownPlatform(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	url := attester(t, "nonsense", tdxBinding(operatorPub))
	if _, err := LoadMeasuredOperatorKey(context.Background(), url, ""); err == nil {
		t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
	}
}

// The self-report must be non-replayable: the code asks the verifier to bind a
// fresh nonce, and a stub reporting success without one would pass a replay.
func TestSelfReportBindsAFreshNonce(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	stub := testattest.New(t)
	stub.SetPlatform(types.Platform(teetypes.PlatformSNP))
	v := testattest.PassingVerdict("")
	v.Claims.InitData = snpBinding(operatorPub)
	stub.SetVerdict(v)

	if _, err := LoadMeasuredOperatorKey(context.Background(), stub.URL, ""); err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("verify requests = %d, want 1", len(reqs))
	}
	sent := reqs[0].Params.ExpectedReportData
	if sent == nil || len(sent.Bytes()) == 0 {
		t.Fatal("no expected report data sent; a self-report with no nonce is replayable")
	}
	var zero [64]byte
	if string(sent.Bytes()) == string(zero[:len(sent.Bytes())]) {
		t.Fatal("expected report data is all zero, so it is not a fresh nonce")
	}
}
