package attestationclient

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func rtmrHex(b byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{b}), launchMeasurementSize)
}

func rtmrBytes(t *testing.T, b byte) []byte {
	t.Helper()
	d, err := hex.DecodeString(rtmrHex(b))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func respWithRTMRs(t *testing.T, platform map[string]string) types.VerifyResponse {
	t.Helper()
	var pd map[string]any
	if platform != nil {
		pd = make(map[string]any, len(platform))
		for k, v := range platform {
			pd[k] = v
		}
	}
	return types.VerifyResponse{Result: types.VerificationResult{
		Claims: types.Claims{PlatformData: pd},
	}}
}

func TestEnforceRTMRs(t *testing.T) {
	good := map[string]string{
		"rtmr_0": rtmrHex(0x00),
		"rtmr_1": rtmrHex(0x11),
		"rtmr_2": rtmrHex(0x22),
		"rtmr_3": rtmrHex(0x33),
	}

	t.Run("no pins accepts anything", func(t *testing.T) {
		if err := EnforceRTMRs(respWithRTMRs(t, nil), nil); err != nil {
			t.Fatalf("EnforceRTMRs: %v", err)
		}
	})

	t.Run("matching pins accepted", func(t *testing.T) {
		pinned := map[int][]byte{1: rtmrBytes(t, 0x11), 2: rtmrBytes(t, 0x22)}
		if err := EnforceRTMRs(respWithRTMRs(t, good), pinned); err != nil {
			t.Fatalf("EnforceRTMRs: %v", err)
		}
	})

	// The whole point: a host boots a different guest image, so the kernel and
	// command line differ while MRTD is unchanged.
	t.Run("substituted guest refused", func(t *testing.T) {
		swapped := map[string]string{}
		for k, v := range good {
			swapped[k] = v
		}
		swapped["rtmr_2"] = rtmrHex(0xee)
		pinned := map[int][]byte{1: rtmrBytes(t, 0x11), 2: rtmrBytes(t, 0x22)}
		err := EnforceRTMRs(respWithRTMRs(t, swapped), pinned)
		if !errors.Is(err, ErrRTMRNotAllowed) || !strings.Contains(err.Error(), "RTMR[2]") {
			t.Fatalf("error = %v, want a RTMR[2] mismatch", err)
		}
	})

	// An SNP quote carries no RTMRs. Pinning one and getting nothing back is a
	// refusal — silently passing would make the pin decorative on the platform
	// it was added for.
	t.Run("pinned but unreported refused", func(t *testing.T) {
		err := EnforceRTMRs(respWithRTMRs(t, nil), map[int][]byte{1: rtmrBytes(t, 0x11)})
		if !errors.Is(err, ErrRTMRNotAllowed) || !strings.Contains(err.Error(), "not reported") {
			t.Fatalf("error = %v, want a not-reported refusal", err)
		}
	})

	t.Run("malformed register refused", func(t *testing.T) {
		for _, tc := range []struct{ name, value string }{
			{"not hex", "zzzz"},
			{"wrong length", hex.EncodeToString([]byte{1, 2, 3})},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := EnforceRTMRs(respWithRTMRs(t, map[string]string{"rtmr_1": tc.value}),
					map[int][]byte{1: rtmrBytes(t, 0x11)})
				if !errors.Is(err, ErrRTMRNotAllowed) {
					t.Fatalf("error = %v, want ErrRTMRNotAllowed", err)
				}
			})
		}
	})

	t.Run("out of range index refused", func(t *testing.T) {
		err := EnforceRTMRs(respWithRTMRs(t, good), map[int][]byte{4: rtmrBytes(t, 0x11)})
		if !errors.Is(err, ErrRTMRNotAllowed) {
			t.Fatalf("error = %v, want ErrRTMRNotAllowed", err)
		}
	})

	// Errors name the lowest failing register regardless of map iteration
	// order, so an operator does not get a different message each run.
	t.Run("error names the lowest failing register", func(t *testing.T) {
		pinned := map[int][]byte{1: rtmrBytes(t, 0xaa), 2: rtmrBytes(t, 0xbb), 3: rtmrBytes(t, 0xcc)}
		for i := 0; i < 20; i++ {
			err := EnforceRTMRs(respWithRTMRs(t, good), pinned)
			if err == nil || !strings.Contains(err.Error(), "RTMR[1]") {
				t.Fatalf("error = %v, want RTMR[1] every time", err)
			}
		}
	})
}
