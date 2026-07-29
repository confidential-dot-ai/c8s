// Live-allowlist config claims: keeping the RA-TLS serving certificate's
// allowlistDigest equal to what CDS is actually serving, so a client that
// attests CDS once learns the current admission policy rather than the one
// loaded at boot. Trust semantics: docs/ratls.md.

package cds

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// reissuePollInterval bounds how long the serving certificate may lag a live
// allowlist change. Allowlist writes are operator actions (rare), so this
// costs one indexed read per tick and re-issues only on an actual change.
const reissuePollInterval = 2 * time.Second

// liveAllowlistDigest is the canonical digest of the allowlist CDS is serving
// right now — the same bytes GET /allowlist returns, so a client can hash the
// response it received and compare against the attested claim without
// re-canonicalizing anything.
func liveAllowlistDigest(store *allowlist.Store) ([]byte, error) {
	doc, _, err := store.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load live allowlist: %w", err)
	}
	return doc.CanonicalDigest()
}

// watchAllowlistReissue re-issues the RA-TLS serving certificate whenever the
// live allowlist digest changes.
//
// This is what makes a long-lived client cache correct without a staleness
// window. The allowlist digest is bound into REPORTDATA, so it cannot be
// updated in place — the certificate itself has to be replaced. A client
// therefore caches the verified certificate by fingerprint and re-attests
// exactly when the fingerprint changes, which is exactly when the policy
// changed. Cache invalidation is driven by the event that matters instead of
// by a timeout someone has to tune.
//
// It polls the store rather than hooking each mutation deliberately: every
// mutation bumps the same version row, so a poll cannot be bypassed by a
// future write path that forgets to call a hook. The lag is bounded by
// interval, and a certificate that briefly lags is fail-closed anyway — a
// client hashing GET /allowlist sees a mismatch against the attested digest
// and refuses, rather than accepting a policy nobody attested.
// swap is CertManager.SwapProvider, taken as a function so the re-issue policy
// can be tested without a live attestation path.
func watchAllowlistReissue(
	ctx context.Context,
	store *allowlist.Store,
	swap func(context.Context, ratls.CertProvider) error,
	claims ratls.ConfigClaims,
	newProvider func(*ratls.ConfigClaims) ratls.CertProvider,
	interval time.Duration,
) {
	last := append([]byte(nil), claims.AllowlistDigest...)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := liveAllowlistDigest(store)
			if err != nil {
				slog.Error("allowlist re-issue: cannot read live allowlist", "error", err)
				continue
			}
			if bytes.Equal(current, last) {
				continue
			}

			// Copy before mutating: the caller's claims stay the baseline for
			// every subsequent re-issue, so a failed swap cannot leave the
			// next attempt building on a half-applied value.
			next := claims
			next.AllowlistDigest = current

			if err := swap(ctx, newProvider(&next)); err != nil {
				// Keep `last` unchanged so the next tick retries. Serving
				// continues on the previous certificate, which still attests a
				// digest CDS genuinely served — stale, never forged.
				slog.Error("allowlist re-issue: cannot swap serving certificate", "error", err)
				continue
			}

			slog.Info("re-issued RA-TLS serving certificate for allowlist change",
				"allowlist_digest", fmt.Sprintf("%x", current),
				"previous", fmt.Sprintf("%x", last))
			last = current
		}
	}
}
