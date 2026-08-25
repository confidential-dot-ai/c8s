package attestationclient

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	digestA = "aa11" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	digestB = "bb22" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	regA1   = "1111" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	regA2   = "2222" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	regB1   = "3333" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evidence(t *testing.T, digest string, rtmrs map[string]string) types.VerifyResponse {
	t.Helper()
	var resp types.VerifyResponse
	resp.Result.Claims.LaunchDigest = digest
	if rtmrs != nil {
		raw, err := json.Marshal(rtmrs)
		if err != nil {
			t.Fatal(err)
		}
		resp.Result.Claims.PlatformData = raw
	}
	return resp
}

func entryTDX(t *testing.T, name, digest string, r1, r2 string) measurements.Entry {
	t.Helper()
	e := measurements.Entry{Name: name, Digest: mustHex(t, digest), RTMRs: map[int][]byte{}}
	if r1 != "" {
		e.RTMRs[1] = mustHex(t, r1)
	}
	if r2 != "" {
		e.RTMRs[2] = mustHex(t, r2)
	}
	return e
}

// The bug this feature exists for: image A's MRTD with image B's registers.
// Pinning the two separately accepts it; one tuple per image does not.
func TestEnforceEntriesRejectsCrossedTuple(t *testing.T) {
	entries := []measurements.Entry{
		entryTDX(t, "image-a", digestA, regA1, regA2),
		entryTDX(t, "image-b", digestB, regB1, ""),
	}
	crossed := evidence(t, digestA, map[string]string{"rtmr_1": regB1, "rtmr_2": regA2})
	if err := EnforceEntries(crossed, entries, string(types.PlatformTdx)); err == nil {
		t.Fatal("accepted image A's digest with image B's RTMR[1]")
	}

	matched := evidence(t, digestA, map[string]string{"rtmr_1": regA1, "rtmr_2": regA2})
	if err := EnforceEntries(matched, entries, string(types.PlatformTdx)); err != nil {
		t.Fatalf("rejected a whole matching image: %v", err)
	}
	second := evidence(t, digestB, map[string]string{"rtmr_1": regB1})
	if err := EnforceEntries(second, entries, string(types.PlatformTdx)); err != nil {
		t.Fatalf("rejected the second pinned image: %v", err)
	}
}

func TestEnforceEntriesRefusals(t *testing.T) {
	entries := []measurements.Entry{entryTDX(t, "image-a", digestA, regA1, "")}
	tdx := string(types.PlatformTdx)

	tests := []struct {
		name string
		resp types.VerifyResponse
		want error
	}{
		{"unpinned digest", evidence(t, digestB, map[string]string{"rtmr_1": regA1}), ErrMeasurementNotAllowed},
		{"missing digest", evidence(t, "", map[string]string{"rtmr_1": regA1}), ErrMeasurementNotAllowed},
		{"malformed digest", evidence(t, "zz"+digestA[2:], nil), ErrInvalidLaunchDigest},
		{"short digest", evidence(t, "aa11", nil), ErrInvalidLaunchDigest},
		{"pinned register not reported", evidence(t, digestA, map[string]string{"rtmr_2": regA2}), ErrRTMRNotAllowed},
		{"register mismatch", evidence(t, digestA, map[string]string{"rtmr_1": regB1}), ErrRTMRNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceEntries(tc.resp, entries, tdx)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}
}

// SNP folds the guest image into its launch digest and reports no registers,
// so entry RTMRs must not be enforced against it.
func TestEnforceEntriesIgnoresRTMRsOnSNP(t *testing.T) {
	entries := []measurements.Entry{entryTDX(t, "image-a", digestA, regA1, regA2)}
	resp := evidence(t, digestA, nil)
	if err := EnforceEntries(resp, entries, string(types.PlatformSnp)); err != nil {
		t.Fatalf("enforced TDX registers against SNP evidence: %v", err)
	}
}

func TestEnforceEntriesEmptyIsNoGate(t *testing.T) {
	if err := EnforceEntries(evidence(t, digestA, nil), nil, string(types.PlatformTdx)); err != nil {
		t.Fatalf("empty entry set gated: %v", err)
	}
}

func TestEnforceEntriesAcceptsUppercaseClaim(t *testing.T) {
	entries := []measurements.Entry{{Name: "a", Digest: mustHex(t, digestA)}}
	resp := evidence(t, strings.ToUpper(digestA), nil)
	if err := EnforceEntries(resp, entries, string(types.PlatformSnp)); err != nil {
		t.Fatalf("rejected an uppercase claim the legacy path accepts: %v", err)
	}
}

// Converted flat flags must decide exactly as the flat path does: a digest
// from the list AND the one pinned register set.
func TestEnforceEntriesMatchesFlatFlagSemantics(t *testing.T) {
	digests := [][]byte{mustHex(t, digestA), mustHex(t, digestB)}
	rtmrs := map[int][]byte{1: mustHex(t, regA1)}
	set := measurements.FromFlags(digests, rtmrs)
	tdx := string(types.PlatformTdx)

	cases := []struct {
		name string
		resp types.VerifyResponse
	}{
		{"first digest, pinned register", evidence(t, digestA, map[string]string{"rtmr_1": regA1})},
		{"second digest, pinned register", evidence(t, digestB, map[string]string{"rtmr_1": regA1})},
		{"first digest, wrong register", evidence(t, digestA, map[string]string{"rtmr_1": regB1})},
		{"unpinned digest", evidence(t, "cc33"+digestA[4:], map[string]string{"rtmr_1": regA1})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy := enforceLaunchMeasurement(tc.resp, [][]byte{digests[0], digests[1]})
			if legacy == nil {
				legacy = EnforceRTMRs(tc.resp, rtmrs)
			}
			entries := EnforceEntries(tc.resp, set.Entries, tdx)
			if (legacy == nil) != (entries == nil) {
				t.Errorf("legacy err=%v but entries err=%v", legacy, entries)
			}
		})
	}
}
