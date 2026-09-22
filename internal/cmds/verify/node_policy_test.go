package verify

import (
	"encoding/hex"
	"errors"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

func TestNodePolicyPinsActualEvidence(t *testing.T) {
	path := filepath.Join("..", "..", "..", "internal", "testdata", "node-identities.json")
	plan, err := buildPolicy(config{measurementsConfig: path})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture contains server and agent identities. Constrain this
	// verdict to the server, as a client connecting to CDS does.
	entry := plan.refValues.Images[0]
	plan.refValues.Images = []remote.ImagePin{entry}
	bound := func(key []byte) *teetypes.VerificationResult {
		r := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX}
		r.Claims.LaunchDigest = hex.EncodeToString(entry.Digest)
		r.Claims.PlatformData = map[string]any{}
		for idx, pin := range entry.Registers {
			r.Claims.PlatformData["rtmr_"+string(rune('0'+idx))] = hex.EncodeToString(pin)
		}
		seed := runtimemeasure.Seed(key)
		r.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seed[:])
		return r
	}
	for _, tc := range []struct {
		name   string
		change func(*teetypes.VerificationResult)
		want   bool
	}{
		{"matching server", func(*teetypes.VerificationResult) {}, true},
		{"wrong image", func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = strings.Repeat("ff", 48) }, false},
		{"wrong kernel", func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_1"] = strings.Repeat("ff", 48) }, false},
		{"wrong rootfs", func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_2"] = strings.Repeat("ff", 48) }, false},
		{"agent on same image", func(r *teetypes.VerificationResult) { *r = *bound([]byte("another role key")) }, false},
		{"wrong platform", func(r *teetypes.VerificationResult) { r.Platform = teetypes.PlatformSNP }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bound(entry.Anchor)
			tc.change(r)
			got := newOutcome(config{}, &evidence{platform: "tdx"}, r, nil, plan)
			if got.Verified != tc.want || !got.Pinned {
				t.Fatalf("verdict = %+v", got)
			}
		})
	}
	// Hardware rejection dominates even if all untrusted claim fields match.
	if got := newOutcome(config{}, &evidence{}, bound(entry.Anchor), errors.New("invalid hardware signature"), plan); got.Verified {
		t.Fatal("failed hardware evidence became verified")
	}
	// A matching weak alternative may not borrow a different image's complete
	// RTMR tuple to pass the existing TDX deployment-image requirement.
	complete := entry
	complete.Digest = []byte(strings.Repeat("x", 48))
	weak := entry
	weak.Registers = nil
	plan.refValues.Images = []remote.ImagePin{weak, complete}
	if got := newOutcome(config{}, &evidence{}, bound(entry.Anchor), nil, plan); got.Verified || !strings.Contains(got.Error, "MRTD only") {
		t.Fatalf("weak matching image borrowed unrelated pins: %+v", got)
	}
}

func TestServedNodePolicyDetectsDroppedOperatorKey(t *testing.T) {
	want, err := refvalues.Load(filepath.Join("..", "..", "..", "internal", "testdata", "node-identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	served := want
	served.Images = append([]remote.ImagePin(nil), want.Images...)
	served.Images[0].Anchor = nil
	fail, messages := collectFailures()
	checkServedMeasurements(want, measurementsReport{served: served, fetched: true}, fail)
	if len(*messages) != 2 {
		t.Fatalf("dropped role key did not change the admitted identities: %v", *messages)
	}
}
