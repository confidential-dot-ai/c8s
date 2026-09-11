package cds

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// initDataVerdict is a passing SNP verdict whose claims carry HOST_DATA.
func initDataVerdict(launchDigest string, hostData []byte) testattest.Verdict {
	v := testattest.PassingVerdict(launchDigest)
	v.Claims.InitData = hostData
	return v
}

// The launch match on top of the image match: the same image launched with
// another launchdata commitment (another role, allowlist or operator key) is
// not issued a leaf.
func TestAttestInitDataPinRefusesOtherLaunch(t *testing.T) {
	pinned := bytes.Repeat([]byte{0xaa}, 32)
	stub := testattest.New(t)
	stub.SetVerdict(initDataVerdict("deadbeef", bytes.Repeat([]byte{0xbb}, 32)))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{"deadbeef": true})
	h.InitData = [][]byte{pinned}

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

// Evidence that reports no init-data cannot show which launch it came from:
// pinned means required.
func TestAttestInitDataPinRequiresReportedValue(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(testattest.PassingVerdict("deadbeef"))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{"deadbeef": true})
	h.InitData = [][]byte{bytes.Repeat([]byte{0xaa}, 32)}

	csrPEM, _ := generateCSR(t)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// Either pinned launch is issued a leaf: the CDS accepts the leader and the
// follower commitments side by side.
func TestAttestInitDataPinIssuesForAnyPinnedLaunch(t *testing.T) {
	leader := bytes.Repeat([]byte{0xaa}, 32)
	follower := bytes.Repeat([]byte{0xbb}, 32)
	for name, reported := range map[string][]byte{"leader": leader, "follower": follower} {
		t.Run(name, func(t *testing.T) {
			stub := testattest.New(t)
			stub.SetVerdict(initDataVerdict("deadbeef", reported))

			h := newTestAttestHandler(t, stub.URL, map[string]bool{"deadbeef": true})
			h.InitData = [][]byte{leader, follower}

			csrPEM, _ := generateCSR(t)
			if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// No pin keeps today's behaviour: the launch field is not consulted.
func TestAttestWithoutInitDataPinIgnoresTheField(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(initDataVerdict("deadbeef", bytes.Repeat([]byte{0xbb}, 32)))

	h := newTestAttestHandler(t, stub.URL, map[string]bool{"deadbeef": true})

	csrPEM, _ := generateCSR(t)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}
