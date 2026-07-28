package credrelease

import (
	"strings"
	"testing"
)

func TestNewCmdDefaultsAndHelp(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "cred-release" {
		t.Fatalf("Use = %q, want cred-release", cmd.Use)
	}

	// The long help walks the whole trust story; pin one phrase per sentence.
	for _, phrase := range []string{
		"cred-release serves an RA-TLS endpoint that issues a short-lived",
		"kube client certificate to a caller who proves possession of the",
		"operator key whose public half was bound into RTMR[3] at launch.",
		"It gives an external operator console-free, non-TOFU cluster-admin",
		"access with no pre-shared secret and no trust in the host. The cert",
		"is signed by the cluster's client CA and the kubeconfig anchors to",
		"the serving CA (RKE2 paths by default; any distribution works via",
		"--client-ca-cert/--client-ca-key/--server-ca-cert",
		"three are /etc/kubernetes/pki/ca.crt).",
	} {
		if !strings.Contains(cmd.Long, phrase) {
			t.Errorf("Long help missing %q", phrase)
		}
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
