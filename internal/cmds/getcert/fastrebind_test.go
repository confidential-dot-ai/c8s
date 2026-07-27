package getcert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The renewal loop's fast-rebind state machine: a claim-free first issuance
// (claimsPending) polls fast; once the claim binds (claimsBound) or the pod does
// not use the broker (claimsNotApplicable) it settles to the renew interval.
func TestShouldFastRebind(t *testing.T) {
	cases := []struct {
		name       string
		fastRebind bool
		state      claimState
		want       bool
	}{
		{"disabled/pending", false, claimsPending, false},
		{"disabled/bound", false, claimsBound, false},
		{"enabled/pending", true, claimsPending, true},
		{"enabled/bound", true, claimsBound, false},
		{"enabled/notApplicable", true, claimsNotApplicable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFastRebind(tc.fastRebind, tc.state); got != tc.want {
				t.Fatalf("shouldFastRebind(%v, %v) = %v, want %v", tc.fastRebind, tc.state, got, tc.want)
			}
		})
	}
}

// A pending claim is (re)issued only outside fast mode; in fast mode it is a
// no-op so the claim-free cert is not rewritten every few seconds during startup.
func TestShouldIssue(t *testing.T) {
	cases := []struct {
		name  string
		fast  bool
		state claimState
		want  bool
	}{
		{"fast/pending is skipped", true, claimsPending, false},
		{"fast/bound issues", true, claimsBound, true},
		{"fast/notApplicable issues", true, claimsNotApplicable, true},
		{"normal/pending issues", false, claimsPending, true},
		{"normal/bound issues", false, claimsBound, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldIssue(tc.fast, tc.state); got != tc.want {
				t.Fatalf("shouldIssue(%v, %v) = %v, want %v", tc.fast, tc.state, got, tc.want)
			}
		})
	}
}

func TestRenewCadence(t *testing.T) {
	cfg := config{RenewInterval: 6 * time.Hour, WorkloadClaimsRebind: 5 * time.Second}
	if got := renewCadence(true, cfg); got != cfg.WorkloadClaimsRebind {
		t.Fatalf("fast cadence = %v, want %v", got, cfg.WorkloadClaimsRebind)
	}
	if got := renewCadence(false, cfg); got != cfg.RenewInterval {
		t.Fatalf("normal cadence = %v, want %v", got, cfg.RenewInterval)
	}
}

// The flag ships on by default so a pod that uses the broker binds its claim in
// seconds without any operator wiring; the default is inert without the broker.
func TestRebindFlagDefaultOn(t *testing.T) {
	cmd := NewCmd()
	got, err := cmd.Flags().GetDuration("workload-claims-rebind-interval")
	if err != nil {
		t.Fatal(err)
	}
	if got != 5*time.Second {
		t.Fatalf("default --workload-claims-rebind-interval = %v, want 5s", got)
	}
}

// Without the broker, a renewal tick always issues and reports the claim as not
// applicable — the fast-rebind additions are inert for non-broker get-cert users
// (tls-lb, nginx sidecars), which is the compatibility property this PR relies on.
func TestRenewOnceWithoutBrokerIssues(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
	}
	client := plaintextCDSClient(cfg.CDSURL)

	// fast=true must not suppress issuance when the pod does not use the broker:
	// state is claimsNotApplicable, so shouldIssue is true regardless.
	state, issued, err := renewOnce(context.Background(), cfg, client, true)
	if err != nil {
		t.Fatalf("renewOnce: %v", err)
	}
	if state != claimsNotApplicable {
		t.Fatalf("state = %v, want claimsNotApplicable", state)
	}
	if !issued {
		t.Fatal("issued = false, want a certificate to be written")
	}
	if got, err := os.ReadFile(cfg.OutPath); err != nil || string(got) != chain {
		t.Fatalf("written cert mismatch: err=%v", err)
	}
}
