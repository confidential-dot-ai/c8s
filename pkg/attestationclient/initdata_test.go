package attestationclient

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func initDataResp(reported []byte) types.VerifyResponse {
	return types.VerifyResponse{Result: teetypes.VerificationResult{
		SignatureValid: true,
		Claims:         types.Claims{InitData: reported},
	}}
}

// The init-data gate: any pinned value passes, everything else — including a
// missing field and a pin sized for the other platform — is a refusal.
func TestEnforceInitData(t *testing.T) {
	hostData := bytes.Repeat([]byte{0xaa}, 32)
	other := bytes.Repeat([]byte{0xbb}, 32)
	mrconfigID := bytes.Repeat([]byte{0xcc}, 48)

	cases := []struct {
		name     string
		reported []byte
		pinned   [][]byte
		wantErr  bool
	}{
		{"no pin, nothing reported", nil, nil, false},
		{"no pin, something reported", hostData, nil, false},
		{"single pin matches", hostData, [][]byte{hostData}, false},
		{"second of two pins matches", hostData, [][]byte{other, hostData}, false},
		{"TDX width matches", mrconfigID, [][]byte{mrconfigID}, false},
		{"pinned but not reported", nil, [][]byte{hostData}, true},
		{"mismatch", other, [][]byte{hostData}, true},
		{"SNP pin against TDX width", mrconfigID, [][]byte{hostData}, true},
		{"prefix is not a match", hostData[:31], [][]byte{hostData}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceInitData(initDataResp(tc.reported), tc.pinned)
			if tc.wantErr {
				if !errors.Is(err, ErrInitDataNotAllowed) {
					t.Fatalf("err = %v, want ErrInitDataNotAllowed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// The init-data pin is enforced on both pin forms: an image match on the
// entry path or the flat path never stands in for the launch match.
func TestEnforcePinsAppliesInitDataOnEveryPinForm(t *testing.T) {
	digest := bytes.Repeat([]byte{0x11}, 48)
	hostData := bytes.Repeat([]byte{0xaa}, 32)
	resp := types.VerifyResponse{Result: teetypes.VerificationResult{
		SignatureValid: true,
		Claims:         types.Claims{LaunchDigest: hex.EncodeToString(digest), InitData: bytes.Repeat([]byte{0xbb}, 32)},
	}}
	entry := measurements.Entry{Name: "node", Digest: digest}

	for name, policy := range map[string]EvidencePolicy{
		"flat":           {Measurements: [][]byte{digest}, InitData: [][]byte{hostData}},
		"entries":        {Entries: []measurements.Entry{entry}, InitData: [][]byte{hostData}},
		"unpinned image": {InitData: [][]byte{hostData}},
	} {
		t.Run(name, func(t *testing.T) {
			err := enforcePins(resp, policy, string(types.PlatformSnp))
			if !errors.Is(err, ErrInitDataNotAllowed) {
				t.Fatalf("err = %v, want ErrInitDataNotAllowed", err)
			}
		})
	}
	// The same evidence passes once the reported value is pinned.
	ok := EvidencePolicy{Measurements: [][]byte{digest}, InitData: [][]byte{bytes.Repeat([]byte{0xbb}, 32)}}
	if err := enforcePins(resp, ok, string(types.PlatformSnp)); err != nil {
		t.Fatalf("matching init-data refused: %v", err)
	}
}
