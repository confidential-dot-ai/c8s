package policymeasure

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestNewCmdDefaults(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "policy-measure" {
		t.Fatalf("Use = %q, want policy-measure", cmd.Use)
	}
	flags := cmd.Flags()
	for _, tc := range []struct {
		name string
		want string
	}{
		{"platform", ""},
		{"policy-dir", "/run/confai/policy"},
		{"opkey-disk", "/dev/disk/by-label/opkeydata"},
		{"policy-disk", "/dev/disk/by-label/policydata"},
		{"operator-pubkey", "/etc/confai/operator-pubkey"},
	} {
		flag := flags.Lookup(tc.name)
		if flag == nil {
			t.Errorf("flag %q not registered", tc.name)
			continue
		}
		if flag.DefValue != tc.want {
			t.Errorf("flag %q default = %q, want %q", tc.name, flag.DefValue, tc.want)
		}
	}
	// Omitting --platform is a usage error, not a tdx default.
	if pf := flags.Lookup("platform"); pf == nil || pf.Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Error("--platform is not marked required")
	}
}
