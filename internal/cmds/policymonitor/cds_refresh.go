//go:build linux

package policymonitor

// Runtime half of the hybrid image-policy allowlist.
//
// The baked bootstrap-allowlist.json (on the dm-verity root) is the SEED:
// it lets the guest enforce from t=0 with no network. This loop keeps the
// in-VM allowlist current with operator additions CDS has accepted by
// polling CDS's `/allowlist` over RA-TLS and merging the result on top of
// the seed. It reuses exactly the mechanism the host nri-image-policy
// worker uses (pkg/ratls RA-TLS client pinned to cds.measurements +
// pkg/allowlistclient), so the in-guest enforcer and the host enforcer
// pull from the same authenticated source. See docs/kata-image-policy.md.
//
// Gated on a configured CDS URL: with C8S_CDS_URL unset the monitor
// stays baked-seed-only and never opens the network.
//
// It does not run until a CDS measurement is pinned, which --cvm-mode=pod
// does not yet deliver.

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// runAllowlistRefresh builds the RA-TLS-pinned CDS allowlist client and
// polls it on cfg.RefreshInterval, merging each response into a. It runs
// until ctx is cancelled. Construction failures (bad measurements, RA-TLS
// setup) disable refresh but never crash the monitor — the baked seed
// still enforces.
func runAllowlistRefresh(ctx context.Context, logger *slog.Logger, cfg *Config, a *allowlist, overlay *policyOverlay, state *refreshState) {
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil {
		disableRefresh(logger, state, reasonBadMeasurements, a, "error", err)
		return
	}
	if len(measurements) == 0 {
		// Fail closed: with C8S_CDS_URL set but no measurements pinned, the
		// RA-TLS handshake would accept any CDS measurement. Disable refresh
		// rather than open that hole — the baked seed keeps enforcing.
		disableRefresh(logger, state, reasonNoMeasurements, a)
		return
	}
	floor, err := types.ParseMinTcb(cfg.MinTCB)
	if err != nil {
		disableRefresh(logger, state, reasonBadMinTCB, a, "error", err)
		return
	}
	httpClient, err := ratls.NewVerifyingHTTPClient(measurements, cfg.AttestationServiceURL, ratls.PackSNPMinTcb(floor))
	if err != nil {
		disableRefresh(logger, state, reasonClientFailed, a, "error", err)
		return
	}
	client := allowlistclient.NewClientWithHTTP(cfg.CDSURL, httpClient)
	state.enable()

	// Per-call deadline so a hung CDS can't wedge this goroutine. Capped at
	// half the refresh interval (and never above refreshCallTimeoutMax) so
	// a stuck call always returns before the next tick fires.
	callTimeout := cfg.RefreshInterval / 2
	if callTimeout > refreshCallTimeoutMax {
		callTimeout = refreshCallTimeoutMax
	}

	logger.Info("allowlist refresh enabled", "cds_url", cfg.CDSURL, "interval", cfg.RefreshInterval, "call_timeout", callTimeout)
	for {
		landed := refreshOnce(ctx, logger, client, a, overlay, callTimeout)
		if landed {
			// The first pull runs before kata-agent has configured the pod
			// network, so it usually fails; a verdict waits for one that
			// lands rather than for the first attempt (see awaitSettled).
			state.settle()
		}
		// Until a pull has landed the network is still coming up, and a
		// container created meanwhile is blocked on that first success. Retry
		// on a short interval so it arrives inside the agent's verdict
		// timeout; drop to the configured cadence once the guest is current.
		delay := cfg.RefreshInterval
		if !landed {
			delay = refreshRetryInterval
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

const (
	// refreshRetryInterval paces retries before the first pull lands.
	refreshRetryInterval = time.Second

	// refreshSettleBudget bounds how long a would-be deny waits for that
	// first pull. Under the agent's own 30s verdict timeout
	// (kata-guest-base/patches/0002-*), so the wait resolves into a real
	// verdict rather than the agent's fail-closed deadline.
	refreshSettleBudget = 20 * time.Second
)

// refreshCallTimeoutMax bounds a single CDS round-trip. The refresh loop
// further clamps to half the configured interval so the call can never
// outlive the next tick.
const refreshCallTimeoutMax = 15 * time.Second

// disableRefresh records why the refresh will not run and says so at ERROR,
// naming the frozen entry count so the line states the blast radius rather than
// only the cause.
func disableRefresh(logger *slog.Logger, state *refreshState, reason string, a *allowlist, args ...any) {
	state.disable(reason)
	// Terminal, so the seed is the final answer: settling here keeps a guest
	// that will never refresh from making every deny serve out the budget.
	state.settle()
	logger.Error("allowlist refresh disabled; enforcement frozen at the baked seed",
		append([]any{"reason", reason, "entries", a.Size()}, args...)...)
}

// refreshOnce pulls the current CDS allowlist. Two layers update: the baked
// floor grows additively with the pulled floor digests (never shrinks — a CDS
// outage or rollback can't loosen digest-only admission), and the workload argv
// policy overlay is replaced only when the pulled version advances the epoch.
// A failed pull is logged and skipped — the existing allowlist and overlay keep
// enforcing, so a CDS outage degrades to "stale but no smaller", never "open".
//
// Reports whether the pull landed, which is what tells a waiting verdict the
// allowlist is CDS-current rather than still the baked seed.
func refreshOnce(ctx context.Context, logger *slog.Logger, client allowlistclient.Client, a *allowlist, overlay *policyOverlay, callTimeout time.Duration) bool {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, version, err := client.List(callCtx)
	if err != nil {
		logger.Warn("allowlist refresh from CDS failed (keeping current allowlist)", "error", err)
		return false
	}

	pulled := make([]string, 0, len(resp.Digests))
	for d := range resp.Digests {
		pulled = append(pulled, d)
	}
	added := a.MergePulled(pulled)

	v, verr := strconv.ParseUint(version, 10, 64)
	if verr != nil {
		logger.Warn("allowlist refresh: unparseable CDS version; keeping current overlay", "version", version, "error", verr)
		return false
	}
	if overlay.apply(resp, v) {
		logger.Info("allowlist refreshed from CDS", "version", v, "workloads", len(resp.Workloads), "floor_added", added, "floor_total", a.Size())
	} else {
		logger.Warn("allowlist refresh: ignoring rolled-back CDS version; keeping current overlay", "version", v, "floor_added", added, "floor_total", a.Size())
	}
	return true
}

// splitCSV trims and splits a comma-separated env value into non-empty
// fields. "" → nil.
func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
