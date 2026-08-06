// Package sidecar holds the CDS-release plumbing shared by the get-secret and
// get-volume sidecars: the config they render from the webhook, the mTLS
// client bound to the pod's leaf, the challenge/sandbox-token dance around
// each store request, and the retry loop that turns "not released yet" into
// bounded patience. The two commands differ only in what they do with the
// released bytes.
package sidecar

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// inventoryEndpoint is where the sandbox token is redeemed. A package variable
// only so tests can point it at a socket they control; production always uses
// the compiled path, which is what stops a control-plane value redirecting the
// redemption to a rogue inventory (docs/getcert-workload-binding.md, Corner 5).
// Unexported so that guarantee holds by visibility; tests use
// SetInventoryEndpointForTest.
var inventoryEndpoint = workloadclaims.InventoryEndpoint

// SetInventoryEndpointForTest points the redemption endpoint at a socket the
// test controls, restoring the compiled path on cleanup. Requiring a
// testing.TB keeps the override out of reach of production code.
func SetInventoryEndpointForTest(t testing.TB, f func() string) {
	prev := inventoryEndpoint
	inventoryEndpoint = f
	t.Cleanup(func() { inventoryEndpoint = prev })
}

// Config is the release plumbing every sidecar needs. The webhook renders all
// of it; each command adds its own fields for what it fetches and where it
// puts the result.
type Config struct {
	CDSURL            string
	AttestationApiURL string
	Measurements      []string

	CertPath string
	KeyPath  string

	// WorkloadClaimsGuest selects the kata shape: the inventory (and any
	// node-local daemons) are inside the guest, reached on guest loopback
	// rather than over sockets a kata guest cannot mount.
	WorkloadClaimsGuest bool

	Attempts         int
	RetryInterval    time.Duration
	RequestTimeout   time.Duration
	InventoryTimeout time.Duration
}

// endpoint is the compiled inventory endpoint for this sidecar's shape. The
// flag selects between two baked values, never an address.
func (c Config) endpoint() string {
	if c.WorkloadClaimsGuest {
		return workloadclaims.GuestInventoryEndpoint()
	}
	return inventoryEndpoint()
}

// BindFlags registers the flags shared by every sidecar. requestTimeoutUsage
// and workloadClaimsGuestUsage are per-command: get-volume's request timeout
// also covers the node agent, and its guest shape also moves the volume
// daemon onto guest loopback.
func BindFlags(f *pflag.FlagSet, cfg *Config, requestTimeoutUsage, workloadClaimsGuestUsage string) {
	f.StringVar(&cfg.CDSURL, "cds-url", "", "https base URL of CDS")
	f.StringVar(&cfg.AttestationApiURL, "attestation-api-url", "", "local attestation-api used to verify CDS's RA-TLS certificate")
	f.StringSliceVar(&cfg.Measurements, "measurements", nil, "SHA-384 hex launch measurement(s) CDS must present (repeatable; empty pins none, UNSAFE)")
	f.StringVar(&cfg.CertPath, "cert", "/run/c8s/certs/tls.crt", "the pod's CDS-issued certificate, presented to CDS")
	f.StringVar(&cfg.KeyPath, "key", "/run/c8s/certs/tls.key", "private key for --cert")
	f.IntVar(&cfg.Attempts, "attempts", 60, "how many times to try before failing; release is refused until every main container is running, so retries are expected")
	f.DurationVar(&cfg.RetryInterval, "retry-interval", 5*time.Second, "wait between attempts")
	f.DurationVar(&cfg.RequestTimeout, "request-timeout", 10*time.Second, requestTimeoutUsage)
	f.DurationVar(&cfg.InventoryTimeout, "inventory-timeout", 5*time.Second, "timeout for redeeming a sandbox token from the node's admission inventory")
	f.BoolVar(&cfg.WorkloadClaimsGuest, "workload-claims-guest", false, workloadClaimsGuestUsage)
}

// Validate checks the shared half of a config and canonicalises the CDS URL.
// Each command's own validate covers the fields only it knows about.
func (c *Config) Validate() error {
	if c.CDSURL == "" {
		return fmt.Errorf("--cds-url is required")
	}
	c.CDSURL = strings.TrimRight(c.CDSURL, "/")
	if !strings.HasPrefix(c.CDSURL, "https://") {
		return fmt.Errorf("--cds-url must be https (RA-TLS)")
	}
	if c.AttestationApiURL == "" {
		return fmt.Errorf("--attestation-api-url is required to verify CDS")
	}
	if c.Attempts <= 0 {
		return fmt.Errorf("--attempts must be positive")
	}
	if c.RetryInterval <= 0 || c.RequestTimeout <= 0 || c.InventoryTimeout <= 0 {
		return fmt.Errorf("--retry-interval, --request-timeout and --inventory-timeout must be positive")
	}
	return nil
}

// ParseMeasurements decodes --measurements, warning when the pin is empty.
func (c *Config) ParseMeasurements() ([][]byte, error) {
	measurements, err := ratls.ParseHexMeasurementsList(c.Measurements)
	if err != nil {
		return nil, fmt.Errorf("--measurements: %w", err)
	}
	if len(measurements) == 0 {
		slog.Warn("--measurements empty: the CDS this sidecar hands its sandbox token to is not pinned to a launch measurement. UNSAFE outside development.")
	}
	return measurements, nil
}

// Retry runs one whole release pass at a time, retrying the set.
//
// Retrying is expected, not exceptional: until every main container is running
// the sandbox does not match its workload entry, so early attempts are denied
// by design. The bound turns a genuinely stuck release into a visible failure
// instead of an idle sidecar in a Running pod. The what argument names the
// thing being released ("secret", "volume") in the log lines.
func Retry(ctx context.Context, cfg Config, what string, attempt func(context.Context) error) error {
	var lastErr error
	for n := 1; n <= cfg.Attempts; n++ {
		err := attempt(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if n == cfg.Attempts {
			// The last attempt's error is the one that matters: log it at
			// ERROR so a stuck release shows its real cause in the sidecar's
			// own log, not just the generic per-attempt INFO line.
			slog.Error(what+" release failed on the final attempt",
				"attempt", n, "of", cfg.Attempts, "error", err)
			break
		}
		slog.Info(what+" not released yet; retrying",
			"attempt", n, "of", cfg.Attempts, "retry_in", cfg.RetryInterval, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.RetryInterval):
		}
	}
	return fmt.Errorf("giving up after %d attempts: %w", cfg.Attempts, lastErr)
}
