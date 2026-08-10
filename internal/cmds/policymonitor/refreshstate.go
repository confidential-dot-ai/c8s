//go:build linux

package policymonitor

// Allowlist-refresh posture, tracked as a value rather than a one-shot startup
// log line.
//
// A guest whose refresh never starts enforces its baked seed forever, and
// `c8s allowlist add` has no effect on it. That state is invisible from
// outside: the locked guest denies ReadStreamRequest, so its journal is
// unreachable — kubectl logs on locked-guest pods is empty by design. This
// type carries the state to the two places an operator can reach it: every
// deny decision, and the CDS-facing digests endpoint.

import (
	"context"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Reasons a refresh never starts. Reported verbatim outside the guest, so they
// name the operator-visible consequence, not just the internal cause.
const (
	// reasonNotYetStarted is the pre-resolution value: the refresh goroutine
	// has not yet reported. Never a steady state.
	reasonNotYetStarted = "the CDS refresh loop has not reported yet"

	reasonNoCDSURL = "no CDS URL configured; enforcing the baked seed alone, " +
		"so `c8s allowlist add` does not reach this guest"
	reasonNoMeasurements = "C8S_CDS_URL set but C8S_CDS_MEASUREMENTS empty, and an unpinned CDS " +
		"could serve any allowlist; enforcing the baked seed alone, so `c8s allowlist add` " +
		"does not reach this guest (docs/kata-image-policy.md)"
	reasonBadMeasurements = "C8S_CDS_MEASUREMENTS is not a valid measurement list; enforcing the " +
		"baked seed alone, so `c8s allowlist add` does not reach this guest"
	reasonClientFailed = "the RA-TLS client to CDS could not be built; enforcing the baked seed " +
		"alone, so `c8s allowlist add` does not reach this guest"
)

// refreshState is the allowlist-refresh posture. The zero value is "disabled,
// reason not yet determined" — runMonitor always resolves it before serving.
type refreshState struct {
	mu      sync.RWMutex
	enabled bool
	reason  string

	settleOnce sync.Once
	settled    chan struct{}
}

// settle marks the first refresh outcome known: a pull has landed, or the loop
// has given up for a reason that will not change. Idempotent — later polls do
// not re-signal.
func (s *refreshState) settle() {
	if s == nil {
		return
	}
	s.settleOnce.Do(func() { close(s.settledCh()) })
}

// settledCh lazily allocates the channel so the zero value stays usable, and
// hands back the same one to every caller.
func (s *refreshState) settledCh() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled == nil {
		s.settled = make(chan struct{})
	}
	return s.settled
}

// awaitSettled blocks until the first refresh outcome is known, ctx ends, or
// the budget runs out. It reports nothing: the caller re-reads the allowlist
// either way, so a timeout simply means the decision is made on what the guest
// has — the baked seed. Once settled it returns immediately, so this costs a
// wait only for containers created during the startup window.
func (s *refreshState) awaitSettled(ctx context.Context, budget time.Duration) {
	if s == nil {
		return
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-s.settledCh():
	case <-ctx.Done():
	case <-timer.C:
	}
}

// disable records why the refresh loop will not run. Terminal: every caller is
// a construction failure the loop cannot recover from.
func (s *refreshState) disable(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	s.reason = reason
}

// enable marks the refresh loop live. A later pull failure does not flip it
// back: the loop keeps retrying and the allowlist stays at its current size.
func (s *refreshState) enable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = true
	s.reason = ""
}

// frozenReason is the reason enforcement is stuck at the baked seed, or "" when
// the refresh is live. Attached to deny decisions so a denied workload names its
// own cause.
func (s *refreshState) frozenReason() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.enabled {
		return ""
	}
	return s.reason
}

// report renders the posture for the digests endpoint — the one authenticated
// channel carrying it out of the guest.
func (s *refreshState) report(entries int) workloadclaims.AllowlistRefresh {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return workloadclaims.AllowlistRefresh{Enabled: s.enabled, Reason: s.reason, Entries: entries}
}
