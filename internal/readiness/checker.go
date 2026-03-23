package readiness

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lunal-dev/c8s/pkg/attestationclient"
)

// Checker periodically polls the attestation service and exposes a readiness flag.
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

// Ready returns true when the attestation service is healthy.
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

func (c *Checker) check(ctx context.Context) {
	healthResp, err := c.attestationClient.Health(ctx)
	ready := err == nil && healthResp.Status == "ok"
	c.ready.Store(ready)

	if !ready {
		slog.Warn("readiness check failed: attestation service unhealthy")
	}
}
