//go:build !c8s_node

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

func TestValidateStaticAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name               string
		static             bool
		measurements, rtmr []string
		measurementsConfig string
		guest              bool
		socketDir          string
		wantErr            string
	}{
		{name: "off with flat pins", measurements: []string{"aa"}},
		{name: "off with a relative socket dir", socketDir: "confai"},
		{name: "static alone", static: true},
		{name: "static with a custom socket dir", static: true, socketDir: "/run/node-attest"},
		{name: "static with measurements", static: true, measurements: []string{"aa"}, wantErr: "cannot be combined with --cds-measurements"},
		{name: "static with rtmrs", static: true, rtmr: []string{"1=aa"}, wantErr: "cannot be combined with --cds-measurements"},
		{name: "static with measurements file", static: true, measurementsConfig: "/etc/c8s-measurements/cds.json", wantErr: "cannot be combined with --cds-measurements"},
		{name: "static in the kata guest shape", static: true, guest: true, wantErr: "--workload-claims-guest"},
		{name: "static with a trailing slash", static: true, socketDir: "/run/confai/", wantErr: "--attestation-socket-dir"},
		{name: "static with a relative socket dir", static: true, socketDir: "run/confai", wantErr: "--attestation-socket-dir"},
		{name: "static with a dotted socket dir", static: true, socketDir: "/run/../run/confai", wantErr: "--attestation-socket-dir"},
	} {
		if tc.socketDir == "" {
			tc.socketDir = webhook.DefaultAttestationSocketDir
		}
		err := validateStaticAllowlist(tc.static, tc.measurements, tc.rtmr, tc.measurementsConfig, tc.guest, tc.socketDir)
		if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("validateStaticAllowlist(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
		}
	}
}
