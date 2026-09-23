// Package cdspin builds the RA-TLS-pinned HTTP client a router sidecar uses
// to reach CDS, together with the flags that configure it.
//
// The router pod runs two sidecars that both dial CDS — allowlist-proxy and
// cds-attest — and a client that accepts a CDS the other would refuse is a
// hole in whichever one is laxer. One definition of the flags and one of the
// client keeps them the same pin.
package cdspin

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// Config is the CDS endpoint and the evidence policy it must satisfy.
type Config struct {
	URL                string
	Measurements       []string
	RTMRs              []string
	MeasurementsConfig string
}

// Flags registers the CDS pinning flags on f under the spellings
// allowlist-proxy already uses, so the chart passes one set of arguments to
// both router sidecars.
func (c *Config) Flags(f *pflag.FlagSet) {
	f.StringVar(&c.URL, "cds-url", "", "CDS base URL (must use https/RA-TLS); empty disables the CDS-backed features")
	f.StringSliceVar(&c.Measurements, "cds-measurements", nil, "allowed CDS SHA-384 launch measurement(s), repeatable/comma-separated; empty accepts any attested CDS (unsafe)")
	f.StringSliceVar(&c.RTMRs, "cds-rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> CDS must additionally satisfy, repeatable/comma-separated; ignored when CDS presents SNP evidence (empty pins no registers)")
	f.StringVar(&c.MeasurementsConfig, "measurements-config", "", "path to a measurements config listing the VM images this cluster runs, each matched as a whole image. Any listed image may serve as CDS. Cannot be combined with --cds-measurements or --cds-rtmrs")
}

// Client resolves the pins and returns an HTTP client that completes a
// handshake only with a CDS whose RA-TLS evidence satisfies them. An empty
// pin set is accepted but logged: it trusts any attested CDS.
func (c *Config) Client(attestationAPIURL string, logger *slog.Logger) (*http.Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	// Resolve before the flat fields are read: they feed the pins below.
	pinned, err := cmdsutil.LoadMeasurementsConfig(c.MeasurementsConfig,
		"--measurements-config", "--cds-measurements", "--cds-rtmrs",
		&c.Measurements, &c.RTMRs)
	if err != nil {
		return nil, err
	}
	measurements, err := refvalues.ParseHexMeasurementsList(c.Measurements)
	if err != nil {
		return nil, fmt.Errorf("--cds-measurements: %w", err)
	}
	if len(measurements) == 0 && len(pinned.Images) == 0 {
		logger.Warn("no CDS measurements pinned; accepting any RA-TLS-attested CDS (unsafe outside development)")
	}
	rtmrs, err := refvalues.ParseRTMRPins(c.RTMRs)
	if err != nil {
		return nil, fmt.Errorf("--cds-rtmrs: %w", err)
	}
	client, err := ratls.NewVerifyingHTTPClient(
		ratls.Pins{Measurements: measurements, RTMRs: rtmrs, Images: pinned.Images}, attestationAPIURL)
	if err != nil {
		return nil, fmt.Errorf("CDS RA-TLS client: %w", err)
	}
	return client, nil
}

// ParseURL validates --cds-url. It must be an https origin with nothing else
// in it: a path or query would silently re-target every request built on top
// of it, and only https carries the RA-TLS evidence the pins check.
func ParseURL(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("invalid --cds-url %q", raw)
	}
	if target.Scheme != "https" {
		return nil, fmt.Errorf("--cds-url must use https (RA-TLS), got scheme %q", target.Scheme)
	}
	if target.User != nil || (target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.Fragment != "" {
		return nil, fmt.Errorf("--cds-url must be an origin without credentials, path, query, or fragment")
	}
	return target, nil
}
