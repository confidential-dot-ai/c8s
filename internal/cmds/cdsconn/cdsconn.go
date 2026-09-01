// Package cdsconn builds what an operator CLI needs to reach CDS: an HTTP
// client that has verified the endpoint's attestation, and the operator
// credential that signs a write.
//
// It is shared by `c8s allowlist` and `c8s secrets`, which authorize against the
// same pinned operator keys and reach CDS the same way. The attestation
// decisions — that plaintext http needs --insecure, that a tls-lb front door is
// trusted through its discovery document, that a direct URL is verified by
// RA-TLS — belong in one place, since each is a way to talk to an unattested
// endpoint by mistake.
package cdsconn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/lbdiscovery"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// EnvOperatorKey supplies the operator private key when the flag is unset.
const EnvOperatorKey = "C8S_OPERATOR_KEY"

// Options are the connection and credential flags an operator CLI carries.
// Embed it in a command's option struct and bind Flags to its persistent flags.
type Options struct {
	URL              string
	Measurements     []string
	MeasurementsFile string
	Timeout          time.Duration
	OperatorKey      string
	Insecure         bool

	// Verify is the evidence verifier; a stub in tests. Zero means
	// localverify.Verify.
	Verify localverify.VerifyFunc
}

// BindFlags registers the connection and credential flags on a command's
// persistent flag set, so every operator CLI spells them the same way.
func BindFlags(pf *pflag.FlagSet, o *Options) {
	pf.StringVar(&o.URL, "url", "", "CDS-issued-TLS tls-lb or direct CDS base URL (required); webpki and tee-webpki need a different public-leaf verification flow")
	pf.StringSliceVar(&o.Measurements, "measurements", nil, "trusted endpoint build ID(s) (repeatable/comma-separated); use the tls-lb value for CDS-issued public TLS or the CDS value for a direct URL; empty trusts any attested build (UNSAFE)")
	pf.StringVar(&o.MeasurementsFile, "measurements-file", "", "file of trusted endpoint build IDs, one per line")
	pf.DurationVar(&o.Timeout, "timeout", 15*time.Second, "per-request timeout")
	pf.StringVar(&o.OperatorKey, "operator-key", "", "operator EC private key PEM file, whose public key is pinned on CDS via --operator-keys (env "+EnvOperatorKey+"); required for writes")
	pf.BoolVar(&o.Insecure, "insecure", false, "dev/test only: allow a plaintext http:// CDS URL, skipping RA-TLS attestation of CDS")
}

// Validate checks the flags every subcommand needs.
func (o *Options) Validate() error {
	if strings.TrimSpace(o.URL) == "" {
		return fmt.Errorf("--url is required")
	}
	return nil
}

// HTTPClient builds a client for CDS. An https URL is verified via RA-TLS (CDS
// proves its TEE attestation). Plaintext http is refused unless Insecure is
// set, so a typo'd or downgraded URL never silently writes to an
// unauthenticated endpoint.
func (o *Options) HTTPClient(ctx context.Context) (*http.Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid --url %q", o.URL)
	}

	switch u.Scheme {
	case "http":
		if !o.Insecure {
			return nil, fmt.Errorf("refusing plaintext http:// for CDS (no attestation): use https:// (RA-TLS), or pass --insecure for a dev/test endpoint")
		}
		fmt.Fprintln(os.Stderr, "warning: --url is http:// with --insecure; CDS attestation is NOT verified (dev/test only)")
		return &http.Client{Timeout: o.Timeout}, nil
	case "https":
		measurements, err := o.loadMeasurements()
		if err != nil {
			return nil, err
		}
		if len(measurements) == 0 {
			fmt.Fprintln(os.Stderr, "warning: no --measurements set; accepting any attested endpoint build (UNSAFE)")
		}
		hc, err := o.httpsClient(ctx, measurements)
		if err != nil {
			return nil, err
		}
		hc.Timeout = o.Timeout
		return hc, nil
	default:
		return nil, fmt.Errorf("--url scheme must be http or https, got %q", u.Scheme)
	}
}

// httpsClient builds the attestation-verifying client. A tls-lb front door
// serves a CDS-issued cert with no RA-TLS extension; its trust path is the
// discovery document, so probe for that first and fall back to direct RA-TLS
// serving-cert verification (a port-forwarded CDS) when the target serves none
// — the same routing `c8s verify` uses in auto mode. A discovery document that
// fails verification is a hard error, never a fallback.
func (o *Options) httpsClient(ctx context.Context, measurements [][]byte) (*http.Client, error) {
	probeCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	hc, err := lbdiscovery.NewVerifiedHTTPClient(probeCtx, o.URL, measurements, o.verifyFunc())
	switch {
	case err == nil:
		fmt.Fprintln(os.Stderr, "note: target is a tls-lb front door; verified its discovery attestation and bound this session to the attested connection")
		return hc, nil
	case errors.Is(err, lbdiscovery.ErrNoDiscovery):
		return localverify.NewRATLSHTTPClient(measurements, o.verifyFunc(), o.Timeout), nil
	default:
		return nil, err
	}
}

// loadMeasurements combines Measurements and MeasurementsFile into the raw
// digest byte form RA-TLS verification expects.
func (o *Options) loadMeasurements() ([][]byte, error) {
	hexes := append([]string{}, o.Measurements...)
	if o.MeasurementsFile != "" {
		data, err := os.ReadFile(o.MeasurementsFile)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		hexes = append(hexes, strings.Split(string(data), "\n")...)
	}
	return ratls.ParseHexMeasurementsList(hexes)
}

// Signer builds the operator credential from the flag or the environment. The
// private key never leaves the CLI: it signs a short-lived token bound to the
// exact method, path, and body of one write. It refuses an unpinned endpoint —
// see requirePinnedEndpoint.
func (o *Options) Signer() (*operatorauth.Signer, error) {
	keyPath := o.OperatorKey
	if keyPath == "" {
		keyPath = os.Getenv(EnvOperatorKey)
	}
	if keyPath == "" {
		return nil, fmt.Errorf("operator key required: set --operator-key or %s", EnvOperatorKey)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read operator key: %w", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load operator key: %w", err)
	}
	if err := o.requirePinnedEndpoint(); err != nil {
		return nil, err
	}
	return signer, nil
}

// requirePinnedEndpoint refuses to mint an operator token for an endpoint whose
// build is not pinned. RA-TLS proves the peer is *a* TEE, not that it is the CDS
// this operator meant; with no --measurements, `c8s secrets put` hands a secret,
// and `c8s allowlist` a policy change, to whatever attested thing answered the
// URL. Reads stay a warning (HTTPClient): they carry no credential and no
// payload, and refusing them would break discovery against a fresh cluster.
//
// A plaintext endpoint is left to HTTPClient, which refuses it outright without
// --insecure and announces it with; adding a pinning complaint on top would only
// bury the specific error under a general one.
func (o *Options) requirePinnedEndpoint() error {
	if u, err := url.Parse(o.URL); err == nil && u.Scheme == "http" {
		return nil
	}
	measurements, err := o.loadMeasurements()
	if err != nil {
		return err
	}
	if len(measurements) == 0 {
		return fmt.Errorf("refusing to authorize against an unpinned CDS: --measurements is empty, so any attested build would be accepted and this operator credential would be presented to it. Pass --measurements <endpoint build ID> (or --measurements-file); use the tls-lb value for a CDS-issued public TLS front door, the CDS value for a direct URL")
	}
	return nil
}

func (o *Options) verifyFunc() localverify.VerifyFunc {
	if o.Verify != nil {
		return o.Verify
	}
	return localverify.Verify
}
