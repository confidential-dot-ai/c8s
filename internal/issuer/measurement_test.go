package issuer_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func TestCheckMeasurementNormalizesLaunchDigestCase(t *testing.T) {
	rawEvidence, err := json.Marshal(map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest: "DEADBEEF",
		},
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	claims := &issuer.EARClaims{RawEvidence: rawEvidence}

	if err := issuer.CheckMeasurement(claims, map[string]bool{"deadbeef": true}, "sign-csr"); err != nil {
		t.Fatalf("uppercase launch digest should match lowercase allowlist: %v", err)
	}
}

func TestCheckMeasurementEmptyAllowlistPasses(t *testing.T) {
	claims := &issuer.EARClaims{}
	if err := issuer.CheckMeasurement(claims, nil, "ep"); err != nil {
		t.Fatalf("empty allowlist should pass: %v", err)
	}
}

func TestCheckMeasurementNotAllowed(t *testing.T) {
	rawEvidence, err := json.Marshal(map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest: "abc123",
		},
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	claims := &issuer.EARClaims{RawEvidence: rawEvidence}
	err = issuer.CheckMeasurement(claims, map[string]bool{"deadbeef": true}, "sign-csr")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonMeasurementDenied {
		t.Errorf("reason = %q, want measurement_denied", ve.Reason)
	}
}

func TestCheckMeasurementExtractFailure(t *testing.T) {
	// RawEvidence without a launch digest -> extraction fails.
	claims := &issuer.EARClaims{RawEvidence: json.RawMessage(`{}`)}
	err := issuer.CheckMeasurement(claims, map[string]bool{"x": true}, "sign-csr")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonMeasurementDenied {
		t.Errorf("reason = %q, want measurement_denied", ve.Reason)
	}
}

func TestNormalizeMeasurement(t *testing.T) {
	if got := issuer.NormalizeMeasurement("  DEADbeef \n"); got != "deadbeef" {
		t.Errorf("NormalizeMeasurement = %q, want deadbeef", got)
	}
}
