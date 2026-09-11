package cds

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The pin must reach the verifier: an issuance gate that never sends the
// expected value gets a clean verdict for any launch of the pinned image.
func TestAttestInitDataPinIsSentToTheVerifier(t *testing.T) {
	pinned := bytes.Repeat([]byte{0xaa}, 32)
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict("deadbeef"))

	h := newTestAttestHandler(t, stub.URL(), map[string]bool{"deadbeef": true})
	h.InitData = pinned

	csrPEM, _ := generateCSR(t)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("verify requests = %d, want 1", len(reqs))
	}
	if !bytes.Equal(reqs[0].Params.ExpectedInitDataHash, pinned) {
		t.Fatalf("expected_init_data_hash = %x, want %x", reqs[0].Params.ExpectedInitDataHash, pinned)
	}
}

// The launch match on top of the image match: the same image launched with
// another launchdata commitment (another role, allowlist or operator key) is
// not issued a leaf.
func TestAttestInitDataPinRefusesOtherLaunch(t *testing.T) {
	stub := mockapi.New(t)
	v := mockapi.PassingVerdict("deadbeef")
	v.InitDataMatch = teetypes.Ptr(false)
	stub.SetVerdict(v)

	h := newTestAttestHandler(t, stub.URL(), map[string]bool{"deadbeef": true})
	h.InitData = bytes.Repeat([]byte{0xaa}, 32)

	csrPEM, _ := generateCSR(t)
	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var envelope types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if envelope.Error != types.ErrorCodeMeasurementDenied {
		t.Fatalf("error code = %q, want %q", envelope.Error, types.ErrorCodeMeasurementDenied)
	}
}

// Evidence whose verdict reports no init-data match cannot show which launch
// it came from: pinned means required.
func TestAttestInitDataPinRequiresAnAffirmativeVerdict(t *testing.T) {
	stub := mockapi.New(t)
	v := mockapi.PassingVerdict("deadbeef")
	v.InitDataMatch = nil
	stub.SetVerdict(v)

	h := newTestAttestHandler(t, stub.URL(), map[string]bool{"deadbeef": true})
	h.InitData = bytes.Repeat([]byte{0xaa}, 32)

	csrPEM, _ := generateCSR(t)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// No pin keeps today's behaviour: the launch field is not consulted, so a
// verdict that reports no match still issues.
func TestAttestWithoutInitDataPinIgnoresTheField(t *testing.T) {
	stub := mockapi.New(t)
	v := mockapi.PassingVerdict("deadbeef")
	v.InitDataMatch = nil
	stub.SetVerdict(v)

	h := newTestAttestHandler(t, stub.URL(), map[string]bool{"deadbeef": true})

	csrPEM, _ := generateCSR(t)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 || len(reqs[0].Params.ExpectedInitDataHash) != 0 {
		t.Fatalf("expected_init_data_hash sent without a pin: %x", reqs[0].Params.ExpectedInitDataHash)
	}
}
