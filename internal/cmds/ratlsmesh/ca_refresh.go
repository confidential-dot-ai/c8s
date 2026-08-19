//go:build linux

package ratlsmesh

import (
	"context"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls/cdsclient"
)

// caBundleRefresh polls CDS /ca and pushes each accepted bundle into the cert
// managers, so mesh peers holding certs from a rotated CA still verify. Shared
// by the host and in-guest runs, which differ only in logPrefix ("cds" vs
// "in-guest cds").
//
// It refreshes through the Provider the cdsUpgrade goroutine provisions with,
// which owns the trust state the refresh continuity-checks against. Ticks
// before the first successful provision fail closed and warn.
type caBundleRefresh struct {
	logger    *slog.Logger
	logPrefix string
	provider  *cdsclient.Provider

	interval  time.Duration
	opTimeout time.Duration

	serverCertMgr *ratls.CertManager
	clientCertMgr *ratls.CertManager
}

func (r caBundleRefresh) run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		refreshCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
		newCerts, err := r.provider.RefreshCABundle(refreshCtx)
		cancel()
		if err != nil {
			r.logger.Warn(r.logPrefix+" CA bundle refresh failed", "error", err)
			continue
		}

		r.serverCertMgr.UpdateCACerts(newCerts)
		if r.clientCertMgr != nil {
			r.clientCertMgr.UpdateCACerts(newCerts)
		}
		r.logger.Debug(r.logPrefix+" CA bundle refreshed", "count", len(newCerts))
	}
}
