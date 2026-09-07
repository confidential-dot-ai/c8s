package launchvalues

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/keys"
)

// TestSignValuesRoundTripsWithRender exercises the two Phase 0b halves
// together: `c8s keys sign-values` (internal/cmds/keys) signs a fragment,
// and Render (this package) verifies and merges it — the same handoff
// c8s-chart-values.sh drives on a real boot, minus the attestation round
// trip (stubbed via the loadMeasuredOperatorKey seam).
func TestSignValuesRoundTripsWithRender(t *testing.T) {
	dir := t.TempDir()

	// Generate an operator keypair the way an operator would with `c8s keys new`.
	genCmd := keys.NewCmd()
	genCmd.SetOut(&bytes.Buffer{})
	genCmd.SetErr(&bytes.Buffer{})
	keyPath := filepath.Join(dir, "operator.key")
	pubPath := filepath.Join(dir, "operator.pub")
	genCmd.SetArgs([]string{"new", "--out", keyPath, "--pub-out", pubPath})
	if err := genCmd.Execute(); err != nil {
		t.Fatalf("keys new: %v", err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	fragPath := filepath.Join(dir, "values.yaml")
	fragYAML := []byte("measurement: \"" + ownMeasurement + "\"\n" +
		"values:\n" +
		"  tlsLb:\n" +
		"    san:\n" +
		"      - example.com\n")
	if err := os.WriteFile(fragPath, fragYAML, 0o644); err != nil {
		t.Fatal(err)
	}

	// Sign it with `c8s keys sign-values`.
	signCmd := keys.NewCmd()
	signCmd.SetOut(&bytes.Buffer{})
	signCmd.SetErr(&bytes.Buffer{})
	signCmd.SetArgs([]string{"sign-values", "--key", keyPath, fragPath})
	if err := signCmd.Execute(); err != nil {
		t.Fatalf("keys sign-values: %v", err)
	}
	sigPath := fragPath + ".sig"
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("sign-values did not write %s: %v", sigPath, err)
	}

	// Render should accept the fragment: the pubkey `c8s keys new` wrote is
	// what LoadMeasuredOperatorKey (faked here) hands back, and the sig
	// verifies under the matching private key.
	withLoader(t, fakeLoader(pubPEM))
	cfg := baseConfig(t, writeOperatorPubkeyFile(t, pubPEM))
	cfg.FragmentPath = fragPath
	cfg.SignaturePath = sigPath

	out, err := Render(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Contains([]byte(out), []byte("example.com")) {
		t.Errorf("rendered values missing the fragment's tlsLb.san entry:\n%s", out)
	}
}
