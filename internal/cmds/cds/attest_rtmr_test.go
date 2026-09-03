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
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	testMRTD  = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	testRTMR1 = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	testRTMR2 = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
)

// tdxVerdict is a passing verdict whose claims carry the TDX register set the
// attestation-api reports in platform_data.
func tdxVerdict(t *testing.T, mrtd, rtmr1, rtmr2 string) testattest.Verdict {
	t.Helper()
	v := testattest.PassingVerdict(mrtd)
	v.Claims.PlatformData = map[string]any{
		"rtmr_0": strings.Repeat("00", 48),
		"rtmr_1": rtmr1,
		"rtmr_2": rtmr2,
		"rtmr_3": strings.Repeat("33", 48),
	}
	return v
}

func postAttestTDX(t *testing.T, h AttestHandler, challenge, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{"quote":"abc"}`)},
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

func rtmrPin(t *testing.T, idx int, hexVal string) map[int][]byte {
	t.Helper()
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		t.Fatal(err)
	}
	return map[int][]byte{idx: b}
}

func mustDecode(t *testing.T, hexVal string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The TDX lane's positive case: MRTD allowlisted and both pinned registers
// matching the report.
func TestAttestTDXWithMatchingRTMRsIssues(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(tdxVerdict(t, testMRTD, testRTMR1, testRTMR2))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{testMRTD: true})
	h.RTMRs = map[int][]byte{1: mustDecode(t, testRTMR1), 2: mustDecode(t, testRTMR2)}

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// The exact TDX-MRTD-ONLY attack shape: same TDVF (matching MRTD), different
// guest kernel (RTMR[1] differs). Must be refused, not issued.
func TestAttestTDXMatchingMRTDButWrongRTMRIsRefused(t *testing.T) {
	otherKernel := strings.Repeat("ab", 48)
	stub := testattest.New(t)
	stub.SetVerdict(tdxVerdict(t, testMRTD, otherKernel, testRTMR2))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{testMRTD: true})
	h.RTMRs = rtmrPin(t, 1, testRTMR1)

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
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

// A pinned register the verdict does not report is a refusal, not a pass — a
// verifier that stopped reporting registers must not silently unpin them.
func TestAttestTDXPinnedRTMRNotReportedIsRefused(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(testattest.PassingVerdict(testMRTD)) // no platform_data at all

	h := newTestAttestHandler(t, stub.URL, map[string]bool{testMRTD: true})
	h.RTMRs = rtmrPin(t, 1, testRTMR1)

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// SNP evidence has no registers and folds the guest image into its launch
// digest, so a configured RTMR pin must not lock SNP guests out of a mixed
// fleet.
func TestAttestSNPUnaffectedByRTMRPins(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")

	h := newTestAttestHandler(t, stub.URL, map[string]bool{"deadbeef": true})
	h.RTMRs = rtmrPin(t, 1, testRTMR1)

	csrPEM, _ := generateCSR(t)
	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// staticEntries parses a static-allowlist measurements config exactly as CDS
// loads it from the chart, so the wire shape (rtmr[3] pinned) is what is
// enforced here.
func staticEntries(t *testing.T, rtmr3 string) []measurements.Entry {
	t.Helper()
	set, err := measurements.Parse([]byte(`{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"static-allowlist","mrtd":"` + testMRTD + `","rtmr":[null,"` + testRTMR1 + `","` + testRTMR2 + `","` + rtmr3 + `"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.StaticEntry(); err != nil {
		t.Fatal(err)
	}
	return set.Entries
}

// Static mode's whole point on /attest: the entry pins RTMR[3], so a pod on
// an unsealed node of the same image (or a node sealed to another bundle)
// presents a different register and is refused even though MRTD, RTMR[1] and
// RTMR[2] all match.
func TestAttestStaticEntryPinsRTMR3(t *testing.T) {
	sealed := strings.Repeat("5e", 48)
	for _, tc := range []struct {
		name     string
		reported string
		want     int
	}{
		{"sealed node", sealed, http.StatusOK},
		{"unsealed node of the same image", strings.Repeat("00", 48), http.StatusForbidden},
		{"node sealed to another bundle", strings.Repeat("6f", 48), http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := tdxVerdict(t, testMRTD, testRTMR1, testRTMR2)
			v.Claims.PlatformData["rtmr_3"] = tc.reported
			stub := testattest.New(t)
			stub.SetVerdict(v)

			h := newTestAttestHandler(t, stub.URL, nil)
			h.Entries = staticEntries(t, sealed)

			csrPEM, _ := generateCSR(t)
			w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden {
				var envelope types.ErrorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
					t.Fatalf("decode error envelope: %v", err)
				}
				if envelope.Error != types.ErrorCodeMeasurementDenied {
					t.Fatalf("error code = %q, want %q", envelope.Error, types.ErrorCodeMeasurementDenied)
				}
			}
		})
	}
}
