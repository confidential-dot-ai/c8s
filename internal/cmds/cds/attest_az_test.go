package cds

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// azLaunchDigest is what Azure evidence reports as the launch digest — on
// AKS it covers the Microsoft paravisor/IGVM, not the c8s guest OS.
const azLaunchDigest = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee"

func azVerdict(t *testing.T, pcrs map[string]string) testattest.Verdict {
	t.Helper()
	v := testattest.PassingVerdict(azLaunchDigest)
	if pcrs != nil {
		platformData, err := json.Marshal(map[string]any{"tpm": pcrs})
		if err != nil {
			t.Fatal(err)
		}
		v.Claims.PlatformData = platformData
	}
	return v
}

func postAttestAz(t *testing.T, h AttestHandler, challenge, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "az-snp", Evidence: json.RawMessage(`{"hcl_report":"abc"}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

// The az positive case: paravisor measurement allowlisted and the pinned
// guest-OS PCR matching the report.
func TestAttestAzWithMatchingPCRIssues(t *testing.T) {
	pcr4 := strings.Repeat("44", 32)
	stub := testattest.New(t)
	stub.SetVerdict(azVerdict(t, map[string]string{"pcr04": pcr4}))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{azLaunchDigest: true})
	h.PCRs = map[int][]byte{4: mustDecode(t, pcr4)}

	csrPEM, _ := generateCSR(t)
	w := postAttestAz(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// The Azure analogue of TDX-MRTD-ONLY: same paravisor (matching launch
// digest), different guest OS (PCR differs). Must be refused, not issued.
func TestAttestAzMatchingMeasurementButWrongPCRIsRefused(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(azVerdict(t, map[string]string{"pcr04": strings.Repeat("ab", 32)}))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{azLaunchDigest: true})
	h.PCRs = map[int][]byte{4: mustDecode(t, strings.Repeat("44", 32))}

	csrPEM, _ := generateCSR(t)
	w := postAttestAz(t, h, issueChallenge(t, h), csrPEM)
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

// A pinned register the verdict does not report is a refusal.
func TestAttestAzPinnedPCRNotReportedIsRefused(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(azVerdict(t, nil)) // no tpm claims at all

	h := newTestAttestHandler(t, stub.URL, map[string]bool{azLaunchDigest: true})
	h.PCRs = map[int][]byte{4: mustDecode(t, strings.Repeat("44", 32))}

	csrPEM, _ := generateCSR(t)
	w := postAttestAz(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// With --init-data-hash set the verify request carries the pin and a false or
// absent init_data_match verdict refuses issuance.
func TestAttestInitDataMismatchIsRefused(t *testing.T) {
	stub := testattest.New(t)
	mismatch := false
	verdict := azVerdict(t, nil)
	verdict.InitDataMatch = &mismatch
	stub.SetVerdict(verdict)

	h := newTestAttestHandler(t, stub.URL, map[string]bool{azLaunchDigest: true})
	h.InitDataHash = mustDecode(t, strings.Repeat("cd", 32))

	csrPEM, _ := generateCSR(t)
	w := postAttestAz(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}

	// The pin must actually have been sent to the verifier.
	reqs := stub.VerifyRequests()
	if len(reqs) == 0 || reqs[len(reqs)-1].Params == nil || reqs[len(reqs)-1].Params.ExpectedInitDataHash == nil {
		t.Fatal("verify request carried no expected_init_data_hash")
	}
	if got := reqs[len(reqs)-1].Params.ExpectedInitDataHash.Bytes(); !bytes.Equal(got, h.InitDataHash) {
		t.Fatalf("expected_init_data_hash = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(h.InitDataHash))
	}
}

// A matching init-data verdict issues.
func TestAttestInitDataMatchIssues(t *testing.T) {
	stub := testattest.New(t)
	match := true
	verdict := azVerdict(t, nil)
	verdict.InitDataMatch = &match
	stub.SetVerdict(verdict)

	h := newTestAttestHandler(t, stub.URL, map[string]bool{azLaunchDigest: true})
	h.InitDataHash = mustDecode(t, strings.Repeat("cd", 32))

	csrPEM, _ := generateCSR(t)
	w := postAttestAz(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// Non-vTPM evidence is unaffected by configured PCR pins.
func TestAttestSNPUnaffectedByPCRPins(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")

	h := newTestAttestHandler(t, stub.URL, map[string]bool{"deadbeef": true})
	h.PCRs = map[int][]byte{4: mustDecode(t, strings.Repeat("44", 32))}

	csrPEM, _ := generateCSR(t)
	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}
