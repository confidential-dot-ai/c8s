// Package secrets implements the `c8s secrets` operator CLI: deposit, read
// back, and delete the secrets the CDS broker releases to attested workloads
// (docs/secrets-broker.md). Every command verifies the broker identity against
// the mesh CA served by the target CDS before any value crosses the wire, and
// values always travel wrapped to the broker encryption key — never as
// plaintext a same-measurement fake CDS could read.
package secrets

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/lbdiscovery"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// envOperatorKey supplies the operator private key when --operator-key is unset.
const envOperatorKey = "C8S_OPERATOR_KEY"

// options holds the flags shared by every subcommand.
type options struct {
	url              string
	measurements     []string
	measurementsFile string
	timeout          time.Duration
	operatorKey      string
	output           string
	insecure         bool

	verify localverify.VerifyFunc
}

// NewCmd returns the `c8s secrets` command tree.
func NewCmd() *cobra.Command {
	return newCmd(localverify.Verify)
}

func newCmd(verify localverify.VerifyFunc) *cobra.Command {
	o := &options{verify: verify}
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Deposit and inspect CDS-brokered secrets",
		Long: `Deposit, read back, and delete the secrets the CDS broker releases to
attested workloads. Secrets are scoped by workload entry and path; a workload
receives exactly the paths its attested container digests are granted by the
allowlist entry's path policy (docs/secrets-broker.md).

Values are wrapped to the broker encryption key before they leave this CLI and
every write is signed with an operator EC key (--operator-key or
C8S_OPERATOR_KEY), the same credential that authorizes allowlist writes.`,
		SilenceUsage: true,
	}

	pf := cmd.PersistentFlags()
	pf.StringVar(&o.url, "url", "", "CDS base URL (required). CDS has no public ingress: reach it via 'kubectl port-forward svc/c8s-cds 8443:8443' then --url https://localhost:8443, or via the tls-lb")
	pf.StringSliceVar(&o.measurements, "measurements", nil, "allowed SHA-384 hex launch measurement(s) of the attested endpoint (repeatable/comma-separated); empty = no pinning (UNSAFE)")
	pf.StringVar(&o.measurementsFile, "measurements-file", "", "file of allowed launch measurements, one hex digest per line")
	pf.DurationVar(&o.timeout, "timeout", 15*time.Second, "per-request timeout")
	pf.StringVar(&o.operatorKey, "operator-key", "", "operator EC private key PEM file, whose public key is pinned on CDS via --operator-keys (env "+envOperatorKey+"); required")
	pf.StringVarP(&o.output, "output", "o", "text", "output format: text or json")
	pf.BoolVar(&o.insecure, "insecure", false, "dev/test only: allow a plaintext http:// CDS URL, skipping RA-TLS attestation of CDS")

	cmd.AddCommand(
		newPutCmd(o),
		newGetCmd(o),
		newDeleteCmd(o),
	)
	return cmd
}

// validate checks the flags every subcommand needs.
func (o *options) validate() error {
	if strings.TrimSpace(o.url) == "" {
		return fmt.Errorf("--url is required")
	}
	if o.output != "text" && o.output != "json" {
		return fmt.Errorf("--output must be text or json, got %q", o.output)
	}
	return nil
}

// httpClient builds the CDS HTTP client: RA-TLS verified for https, plaintext
// only with --insecure (mirrors `c8s allowlist`).
func (o *options) httpClient(ctx context.Context) (*http.Client, error) {
	u, err := url.Parse(o.url)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid --url %q", o.url)
	}
	switch u.Scheme {
	case "http":
		if !o.insecure {
			return nil, fmt.Errorf("refusing plaintext http:// for CDS (no attestation): use https:// (RA-TLS), or pass --insecure for a dev/test endpoint")
		}
		fmt.Fprintln(os.Stderr, "warning: --url is http:// with --insecure; CDS attestation is NOT verified (dev/test only)")
		return &http.Client{Timeout: o.timeout}, nil
	case "https":
		measurements, err := o.loadMeasurements()
		if err != nil {
			return nil, err
		}
		if len(measurements) == 0 {
			fmt.Fprintln(os.Stderr, "warning: no --measurements set; accepting any RA-TLS-attested CDS (UNSAFE)")
		}
		probeCtx, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()
		hc, err := lbdiscovery.NewVerifiedHTTPClient(probeCtx, o.url, measurements, o.verify)
		switch {
		case err == nil:
			fmt.Fprintln(os.Stderr, "note: target is a tls-lb front door; verified its discovery attestation and bound this session to the attested connection")
			return hc, nil
		case errors.Is(err, lbdiscovery.ErrNoDiscovery):
			return localverify.NewRATLSHTTPClient(measurements, o.verify, o.timeout), nil
		default:
			return nil, err
		}
	default:
		return nil, fmt.Errorf("--url scheme must be http or https, got %q", u.Scheme)
	}
}

func (o *options) loadMeasurements() ([][]byte, error) {
	hexes := append([]string{}, o.measurements...)
	if o.measurementsFile != "" {
		data, err := os.ReadFile(o.measurementsFile)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		hexes = append(hexes, strings.Split(string(data), "\n")...)
	}
	return ratls.ParseHexMeasurementsList(hexes)
}

// signer builds the operator credential from the flags or environment.
func (o *options) signer() (*operatorauth.Signer, error) {
	keyPath := o.operatorKey
	if keyPath == "" {
		keyPath = os.Getenv(envOperatorKey)
	}
	if keyPath == "" {
		return nil, fmt.Errorf("operator key required: set --operator-key or %s", envOperatorKey)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read operator key: %w", err)
	}
	return operatorauth.NewSignerFromKeyPEM(keyPEM)
}

// brokerIdentity fetches /ca and /secrets/broker-identity and returns the
// verified (signing, encryption) public keys. The CA bundle rides the same
// RA-TLS channel, so this inherits its pinning — pin --measurements, and run
// `c8s cds verify` out of band for governance, as with every CDS client.
func (o *options) brokerIdentity(ctx context.Context, hc *http.Client) (*brokerClient, error) {
	caPEM, err := getBytes(ctx, hc, o.url+"/ca")
	if err != nil {
		return nil, fmt.Errorf("fetch mesh CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse mesh CA bundle")
	}
	identityJSON, err := getBytes(ctx, hc, o.url+"/secrets/broker-identity")
	if err != nil {
		return nil, fmt.Errorf("fetch broker identity: %w", err)
	}
	return newBrokerClient(hc, o.url, roots, identityJSON)
}

func getBytes(ctx context.Context, hc *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// readValueArg reads a secret value: literal, @file, or - for stdin.
func readValueArg(arg string) ([]byte, error) {
	switch {
	case arg == "-":
		return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	case strings.HasPrefix(arg, "@"):
		return os.ReadFile(strings.TrimPrefix(arg, "@"))
	default:
		return []byte(arg), nil
	}
}

func ctx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
