package main

import "testing"

// The webhook injects containers whose entrypoint is `c8s <subcommand>`
// (internal/webhook: secret-agent-config in c8s-secrets-config, luks-open in
// c8s-luks-open). A subcommand missing from this binary crashloops every
// opted-in pod, so pin their registration.
func TestInjectedSubcommandsRegistered(t *testing.T) {
	for _, name := range []string{"secret-agent-config", "luks-open"} {
		found := false
		for _, c := range rootCmd.Commands() {
			if c.Name() == name {
				found = true
			}
		}
		if !found {
			t.Errorf("webhook-injected subcommand %q is not registered on rootCmd", name)
		}
	}
}
