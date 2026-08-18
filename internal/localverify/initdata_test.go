package localverify

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The Genoa fixture's HOST_DATA is 32 zero bytes; the pin is the digest an
// operator expects the guest's init-data document to hash to.
var genoaHostData = make([]byte, 32)

// A supplied init-data pin reaches the engine and the verdict confirms it:
// the evidence's own HOST_DATA satisfies the pin, and InitDataMatch comes
// back affirmatively true (enforceResult would refuse anything less).
func TestVerify_InitDataPinMatchesEvidence(t *testing.T) {
	platform, evidence := envelopeFixture(t, "snp-evidence-genoa.json")

	res, err := Verify(context.Background(), platform, evidence, Params{ExpectedInitDataHash: genoaHostData})
	if err != nil {
		t.Fatalf("the evidence's own HOST_DATA must satisfy the pin: %v", err)
	}
	if res.InitDataMatch == nil || !*res.InitDataMatch {
		t.Fatal("init_data_match must be affirmatively true when a pin was supplied and enforced")
	}
	if got := hex.EncodeToString(res.Claims.InitData); got != strings.Repeat("00", 32) {
		t.Fatalf("claims.InitData = %q, want the fixture's zero HOST_DATA", got)
	}
}

// The relying-party refusal the issue asks for: evidence whose init-data
// digest differs from the pin is rejected by the verifier, not merely
// reported. This is the engine's refusal — the SNP HOST_DATA and az-snp
// PCR[8] bindings both fail closed, naming the field.
func TestVerify_InitDataPinMismatchIsRefused(t *testing.T) {
	mismatched := bytes.Repeat([]byte{0xab}, 32)

	t.Run("snp HOST_DATA", func(t *testing.T) {
		platform, evidence := envelopeFixture(t, "snp-evidence-genoa.json")
		if _, err := Verify(context.Background(), platform, evidence, Params{ExpectedInitDataHash: mismatched}); err == nil {
			t.Fatal("a HOST_DATA that differs from the pin must be refused")
		} else if !strings.Contains(err.Error(), "HOST_DATA") {
			t.Fatalf("the refusal must name the failing field, got: %v", err)
		}
	})

	// The az-snp fixture's PCR[8] is zero — no init-data was extended into the
	// vTPM — so any pin refuses at the PCR[8] binding.
	t.Run("az-snp PCR[8]", func(t *testing.T) {
		platform, evidence := envelopeFixture(t, "azsnp-evidence-v1.json")
		if _, err := Verify(context.Background(), platform, evidence, Params{ExpectedInitDataHash: mismatched}); err == nil {
			t.Fatal("a PCR[8] binding that differs from the pin must be refused")
		} else if !strings.Contains(err.Error(), "PCR[8]") {
			t.Fatalf("the refusal must name the failing field, got: %v", err)
		}
	})
}

// enforceResult is the fail-closed backstop: a pin the verdict does not
// confirm must fail even when dispatch returned no error.
func TestEnforceResult_InitDataPin(t *testing.T) {
	pin := bytes.Repeat([]byte{0xab}, 32)
	passing := func(match *bool) *teetypes.VerificationResult {
		return &teetypes.VerificationResult{SignatureValid: true, InitDataMatch: match}
	}

	for _, tc := range []struct {
		name    string
		p       Params
		res     *teetypes.VerificationResult
		wantErr bool
	}{
		{"pin confirmed", Params{ExpectedInitDataHash: pin}, passing(teetypes.Ptr(true)), false},
		{"pin unconfirmed", Params{ExpectedInitDataHash: pin}, passing(nil), true},
		{"pin contradicted", Params{ExpectedInitDataHash: pin}, passing(teetypes.Ptr(false)), true},
		{"no pin, no claim", Params{}, passing(nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceResult(tc.res, tc.p)
			if tc.wantErr && err == nil {
				t.Fatal("want a refusal")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want a pass, got: %v", err)
			}
		})
	}
}
