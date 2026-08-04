//go:build linux

package ratlsmesh

import (
	"context"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls/cdsclient"
)

// runCDSUpgrade swaps the server cert manager's provider from self-signed to
// CDS-issued, retrying with backoff until it succeeds, then upgrades the
// client manager once and flips the cert-mode gauge. Shared by the host and
// in-guest runs, which differ only in how the provider is built and in
// logPrefix ("cds" vs "in-guest cds").
func runCDSUpgrade(
	ctx context.Context,
	logger *slog.Logger,
	logPrefix string,
	newProvider func() (*cdsclient.Provider, error),
	retryBackoff, retryMaxBackoff, opTimeout time.Duration,
	serverCertMgr, clientCertMgr *ratls.CertManager,
	m *metrics,
) {
	provider, err := newProvider()
	if err != nil {
		logger.Error(logPrefix+" provider creation failed", "error", err)
		return
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = retryBackoff
	bo.MaxInterval = retryMaxBackoff
	// MaxElapsedTime defaults to 0 (unlimited); ctx cancellation is the only
	// exit.

	_, err = backoff.Retry(ctx, func() (struct{}, error) {
		upgradeCtx, cancel := context.WithTimeout(ctx, opTimeout)
		defer cancel()
		if err := serverCertMgr.SwapProvider(upgradeCtx, provider); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	},
		backoff.WithBackOff(bo),
		backoff.WithNotify(func(err error, d time.Duration) {
			logger.Warn(logPrefix+" certificate upgrade attempt failed (will retry)", "error", err, "backoff", d)
		}),
	)
	if err != nil {
		// ctx cancelled or unrecoverable error from the operation.
		return
	}
	logger.Info(logPrefix + " certificate upgraded from self-signed to cds-issued (server)")

	if clientCertMgr != nil {
		upgradeCtx, cancel := context.WithTimeout(ctx, opTimeout)
		if err := clientCertMgr.SwapProvider(upgradeCtx, provider); err != nil {
			logger.Warn(logPrefix+" client certificate upgrade failed", "error", err)
		} else {
			logger.Info(logPrefix + " certificate upgraded from self-signed to cds-issued (client)")
		}
		cancel()
	}

	m.certMode.Store(1)
}
