//go:build !c8s_node

package main

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

func TestValidateOperatorPlatform(t *testing.T) {
	for _, tc := range []struct {
		platform    string
		kataEnforce bool
		wantErr     string
	}{
		{webhook.HardwarePlatformSNP, true, ""},
		{webhook.HardwarePlatformTDX, true, ""},
		{"", false, ""}, // no kata enforcement: platform unused, empty is fine
		{"", true, "required with --kata-enforce"},
		{"foo", false, "must be"},
	} {
		err := validateOperatorPlatform(tc.platform, tc.kataEnforce)
		if tc.wantErr == "" && err != nil {
			t.Errorf("validateOperatorPlatform(%q, %v) = %v, want nil", tc.platform, tc.kataEnforce, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("validateOperatorPlatform(%q, %v) = %v, want substring %q", tc.platform, tc.kataEnforce, err, tc.wantErr)
		}
	}
}

func TestKataRefusesOperatorPolicyFlattening(t *testing.T) {
	pins := measurements.ReferenceValues{Entries: []measurements.Entry{{OperatorKey: []byte("leader")}}}
	if err := validateOperatorMeasurementsPolicy(pins, true); err == nil || !strings.Contains(err.Error(), "Kata initdata") {
		t.Fatalf("Kata would discard the operator identity: %v", err)
	}
	if err := validateOperatorMeasurementsPolicy(pins, false); err != nil {
		t.Fatalf("node policy refused: %v", err)
	}
	pins.Entries[0].OperatorKey = nil
	if err := validateOperatorMeasurementsPolicy(pins, true); err != nil {
		t.Fatalf("legacy Kata policy refused: %v", err)
	}
}
