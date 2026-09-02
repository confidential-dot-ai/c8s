package attestationclient

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func pcrHex(b byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{b}), pcrDigestSize)
}

func pcrBytes(t *testing.T, b byte) []byte {
	t.Helper()
	d, err := hex.DecodeString(pcrHex(b))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func respWithTPM(t *testing.T, pcrs map[string]string) types.VerifyResponse {
	t.Helper()
	var raw json.RawMessage
	if pcrs != nil {
		b, err := json.Marshal(map[string]any{"tpm": pcrs})
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	return types.VerifyResponse{Result: types.VerificationResult{
		Claims: types.Claims{PlatformData: raw},
	}}
}

func TestEnforcePCRs(t *testing.T) {
	good := map[string]string{
		"pcr04": pcrHex(0x44),
		"pcr08": pcrHex(0x88),
		"pcr11": pcrHex(0x11),
	}

	t.Run("no pins accepts anything", func(t *testing.T) {
		if err := EnforcePCRs("az-snp", respWithTPM(t, nil), nil); err != nil {
			t.Fatalf("EnforcePCRs: %v", err)
		}
	})

	t.Run("matching pins pass on both az platforms", func(t *testing.T) {
		pinned := map[int][]byte{4: pcrBytes(t, 0x44), 11: pcrBytes(t, 0x11)}
		for _, platform := range []string{"az-snp", "az-tdx"} {
			if err := EnforcePCRs(platform, respWithTPM(t, good), pinned); err != nil {
				t.Fatalf("EnforcePCRs(%s): %v", platform, err)
			}
		}
	})

	t.Run("mismatch refuses", func(t *testing.T) {
		pinned := map[int][]byte{4: pcrBytes(t, 0xAB)}
		err := EnforcePCRs("az-snp", respWithTPM(t, good), pinned)
		if !errors.Is(err, ErrPCRNotAllowed) {
			t.Fatalf("err = %v, want ErrPCRNotAllowed", err)
		}
	})

	t.Run("pinned but unreported refuses", func(t *testing.T) {
		pinned := map[int][]byte{7: pcrBytes(t, 0x77)}
		err := EnforcePCRs("az-snp", respWithTPM(t, good), pinned)
		if !errors.Is(err, ErrPCRNotAllowed) {
			t.Fatalf("err = %v, want ErrPCRNotAllowed for an unreported register", err)
		}
	})

	t.Run("no platform data refuses", func(t *testing.T) {
		pinned := map[int][]byte{4: pcrBytes(t, 0x44)}
		err := EnforcePCRs("az-snp", respWithTPM(t, nil), pinned)
		if !errors.Is(err, ErrPCRNotAllowed) {
			t.Fatalf("err = %v, want ErrPCRNotAllowed with no TPM claims", err)
		}
	})

	t.Run("non-az platforms are unaffected", func(t *testing.T) {
		pinned := map[int][]byte{4: pcrBytes(t, 0xAB)}
		for _, platform := range []string{"snp", "gcp-snp", "tdx"} {
			if err := EnforcePCRs(platform, respWithTPM(t, good), pinned); err != nil {
				t.Fatalf("EnforcePCRs(%s): %v, want pins ignored without a vTPM", platform, err)
			}
		}
	})
}

func TestEnforceVerdictInitDataMatch(t *testing.T) {
	pinned := types.NewBase64Bytes([]byte("0123456789abcdef0123456789abcdef"))
	reqWithPin := types.VerifyRequest{Params: &types.VerifyParams{ExpectedInitDataHash: &pinned}}
	match, mismatch := true, false

	respWith := func(initDataMatch *bool) types.VerifyResponse {
		return types.VerifyResponse{Result: types.VerificationResult{
			SignatureValid: true,
			InitDataMatch:  initDataMatch,
		}}
	}

	if err := EnforceVerdict(reqWithPin, respWith(&match)); err != nil {
		t.Fatalf("matching init-data verdict refused: %v", err)
	}
	if err := EnforceVerdict(reqWithPin, respWith(&mismatch)); !errors.Is(err, ErrInitDataMismatch) {
		t.Fatalf("err = %v, want ErrInitDataMismatch on a false verdict", err)
	}
	if err := EnforceVerdict(reqWithPin, respWith(nil)); !errors.Is(err, ErrInitDataMismatch) {
		t.Fatalf("err = %v, want ErrInitDataMismatch on an absent verdict", err)
	}
	// No pin sent: the verdict is not required.
	if err := EnforceVerdict(types.VerifyRequest{}, respWith(nil)); err != nil {
		t.Fatalf("unpinned request required an init-data verdict: %v", err)
	}
}
