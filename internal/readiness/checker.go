package readiness

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
)

// Checker periodically polls the attestation-api and exposes a readiness flag.
type Checker struct {
	ready atomic.Bool

	attestationClient attestationclient.Client
	interval          time.Duration
}

// NewChecker creates a new readiness checker.
func NewChecker(
	attestationClient attestationclient.Client,
	interval time.Duration,
) Checker {
	return Checker{
		attestationClient: attestationClient,
		interval:          interval,
	}
}

// Ready returns true when the attestation-api is healthy.
func (c *Checker) Ready() bool {
	return c.ready.Load()
}

// SetReady sets the readiness state directly. Useful for testing.
func (c *Checker) SetReady(v bool) {
	c.ready.Store(v)
}

// Run starts the background polling loop. It blocks until the context is cancelled.
func (c *Checker) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Run an immediate check before waiting for the first tick
	c.check(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.check(ctx)
		}
	}
}

// maxProbeTimeout bounds a single probe when the poll interval is long.
const maxProbeTimeout = 5 * time.Second

func (c *Checker) check(ctx context.Context) {
	// Per-probe deadline, always under one interval: a peer that accepts the
	// connection and never answers must not park this goroutine.
	probeCtx, cancel := context.WithTimeout(ctx, min(c.interval/2, maxProbeTimeout))
	defer cancel()

	healthResp, err := c.attestationClient.Health(probeCtx)
	ready := err == nil && healthResp.Status == "ok"
	c.ready.Store(ready)

	if !ready {
		slog.Warn("readiness check failed: attestation-api unhealthy")
	}
}
