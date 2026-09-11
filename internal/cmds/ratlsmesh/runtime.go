//go:build linux

package ratlsmesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls/cdsclient"
)

type meshEnvironment interface {
	// configure supplies routing and listeners and initializes the runtime health server.
	configure(*meshRuntime) *Proxy
	start(context.Context, *meshRuntime)
}

type meshRuntime struct {
	logger                       *slog.Logger
	serverTLS, clientTLS         *tls.Config
	serverCertMgr, clientCertMgr *ratls.CertManager
	metrics                      *metrics
	health                       *healthServer
	healthPort                   int
	healthListener               net.Listener
	rotationTimeout              time.Duration
	proxy                        *Proxy
}

func newMeshRuntime(cfg *ratls.ServerConfig, logger *slog.Logger, sessionCacheSize int) (*meshRuntime, error) {
	serverTLS, serverCertMgr, err := ratls.NewServerTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create server TLS config: %w", err)
	}
	clientTLS, clientCertMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:          cfg.ClientPolicy,
		Platform:        cfg.Platform,
		AttestFunc:      cfg.AttestFunc,
		CACert:          cfg.CACert,
		DynamicCACert:   cfg.DynamicCACert,
		CertTTL:         cfg.CertTTL,
		RotationTimeout: cfg.RotationTimeout,
		Logger:          cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create client TLS config: %w", err)
	}
	if sessionCacheSize > 0 {
		clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(sessionCacheSize)
	}
	m := newMetrics()
	if len(cfg.ClientPolicy.Policy.Measurements) > 0 {
		m.measurementPinning.Set(1)
	}
	wrapVerify := func(orig func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
		if orig == nil {
			return nil
		}
		return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			err := orig(rawCerts, chains)
			if err != nil {
				m.attestationFailures.Inc()
			}
			return err
		}
	}
	serverTLS.VerifyPeerCertificate = wrapVerify(serverTLS.VerifyPeerCertificate)
	clientTLS.VerifyPeerCertificate = wrapVerify(clientTLS.VerifyPeerCertificate)
	serverCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Inc() })
	if clientCertMgr != nil {
		clientCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Inc() })
	}
	return &meshRuntime{
		logger: logger, serverTLS: serverTLS, clientTLS: clientTLS,
		serverCertMgr: serverCertMgr, clientCertMgr: clientCertMgr,
		metrics: m, rotationTimeout: cfg.RotationTimeout,
	}, nil
}

func (r *meshRuntime) run(ctx context.Context, env meshEnvironment) error {
	p := env.configure(r)
	r.proxy = p
	p.serverTLS, p.clientTLS = r.serverTLS, r.clientTLS
	p.logger, p.metrics = r.logger, r.metrics
	p.origDstFunc = defaultOrigDstFunc
	p.bufPool = newBufPool(p.pipeBufferSize)
	p.onReady = func() {
		warmupCtx, cancel := context.WithTimeout(ctx, 2*r.rotationTimeout)
		defer cancel()
		if err := r.serverCertMgr.WarmUp(warmupCtx); err != nil {
			r.logger.Error("server certificate warm-up failed", "error", err)
		}
		if r.clientCertMgr != nil {
			if err := r.clientCertMgr.WarmUp(warmupCtx); err != nil {
				r.logger.Error("client certificate warm-up failed", "error", err)
			}
		}
		r.health.ready.Store(true)
	}
	p.onShutdown = func() { r.health.ready.Store(false) }
	go func() {
		if err := r.health.serve(ctx, fmt.Sprintf(":%d", r.healthPort), r.healthListener); err != nil {
			r.logger.Error("health server error", "error", err)
		}
	}()
	env.start(ctx, r)
	return p.Run(ctx)
}

func (r *meshRuntime) startCDS(ctx context.Context, cfg *cdsclient.Config, upgrade cdsUpgrade, interval time.Duration) bool {
	provider, err := cdsclient.NewProvider(cfg, r.logger)
	if err != nil {
		r.logger.Error(upgrade.logPrefix+" provider creation failed", "error", err)
		return false
	}
	upgrade.logger, upgrade.provider = r.logger, provider
	upgrade.serverCertMgr, upgrade.clientCertMgr = r.serverCertMgr, r.clientCertMgr
	upgrade.metrics = r.metrics
	go upgrade.run(ctx)
	go caBundleRefresh{
		logger: r.logger, logPrefix: upgrade.logPrefix, provider: provider,
		interval: interval, opTimeout: upgrade.opTimeout,
		serverCertMgr: r.serverCertMgr, clientCertMgr: r.clientCertMgr,
	}.run(ctx)
	return true
}
