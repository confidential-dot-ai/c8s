package localverify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestVerifyRejectsMalformedRTMRPin(t *testing.T) {
	// Pin validation happens before any evidence is touched, so a nonsense
	// envelope is fine here — the call must not get that far.
	_, err := Verify(context.Background(), "tdx", json.RawMessage(`{}`),
		Params{ExpectedRTMRs: [4][]byte{1: []byte("short")}})
	if err == nil || !strings.Contains(err.Error(), "RTMR[1]") {
		t.Fatalf("undersized RTMR pin accepted (err = %v)", err)
	}
}

func TestVerifyRejectsRTMRPinOnNonTDXPlatform(t *testing.T) {
	// attestation-go consults RTMR pins only on the TDX path. Accepting one for
	// another platform would leave a pin that looks configured and enforces
	// nothing, so Verify must refuse it rather than report a hollow pass.
	pin := make([]byte, 48)
	for _, platform := range []string{"snp", "az-snp", "gcp-snp"} {
		_, err := Verify(context.Background(), platform, json.RawMessage(`{}`),
			Params{ExpectedRTMRs: [4][]byte{3: pin}})
		if err == nil || !strings.Contains(err.Error(), "TDX-only") {
			t.Fatalf("platform %s: RTMR pin accepted (err = %v)", platform, err)
		}
	}
}

func TestCollateralErrorUnwraps(t *testing.T) {
	sentinel := errors.New("kds unreachable")
	if !errors.Is(&CollateralError{Err: sentinel}, sentinel) {
		t.Fatal("CollateralError does not unwrap to its cause")
	}
}
