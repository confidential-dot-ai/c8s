package credrelease

import (
	"testing"
)

func TestNewCmdDefaultsAndHelp(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "cred-release" {
		t.Fatalf("Use = %q, want cred-release", cmd.Use)
	}

	defaults := []struct {
		name string
		want string
	}{
		{"listen", ":8443"},
		{"attestation-api-url", "http://127.0.0.1:8400"},
		{"platform", "tdx"},
		{"client-ca-cert", defaultClientCACert},
		{"client-ca-key", defaultClientCAKey},
		{"server-ca-cert", defaultServerCACert},
		{"cert-ttl", "24h0m0s"},
		{"cert-org", "system:masters"},
		{"cert-cn", "operator"},
	}
	flags := cmd.Flags()
	for _, tt := range defaults {
		flag := flags.Lookup(tt.name)
		if flag == nil {
			t.Errorf("flag %q not registered", tt.name)
			continue
		}
		if flag.DefValue != tt.want {
			t.Errorf("flag %q default = %q, want %q", tt.name, flag.DefValue, tt.want)
		}
	}
}
