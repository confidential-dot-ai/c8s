package policymonitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// A malformed RTMR pin disables sandbox tokens the same way a malformed
// measurement does: fail closed, never silently unpinned.
func TestInstallSandboxTokenSignerDisablesOnBadRTMRs(t *testing.T) {
	cfg := &Config{
		CDSMeasurements: strings.Repeat("ab", 48),
		CDSRTMRs:        "1=zz",
	}
	signers := workloadclaims.NewPendingSignerHolder()
	installSandboxTokenSigner(context.Background(), cfg, testLogger(t), newAdmissionInventory(), signers, time.Now())
	if signers.Ready() {
		t.Fatal("sandbox tokens stayed enabled with an unparseable RTMR pin")
	}
}
