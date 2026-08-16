package main

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
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
