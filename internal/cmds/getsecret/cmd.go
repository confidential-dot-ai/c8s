package getsecret

import (
	"time"

	"github.com/spf13/cobra"
)

// NewCmd returns the cobra subcommand. Registered as a child of `c8s`.
func NewCmd() *cobra.Command {
	var (
		cfg   config
		specs []string
	)
	cmd := &cobra.Command{
		Use:   "get-secret",
		Short: "Fetch this pod's secrets from CDS and write them into the pod",
		Long: `get-secret fetches the secrets a workload is granted and writes each one
to a file for the pod's other containers to read.

It authenticates with the pod's CDS-issued certificate and a sandbox token
redeemed from the node's admission inventory, and CDS releases only when the
containers running in the sandbox match a workload entry holding a grant for
the requested path. That is only true once every main container is running, so
early attempts are refused and get-secret retries — the files appear shortly
after the workload starts, and a consumer must wait for them.

A path the store does not hold yet is created, so the first pod of a workload
to ask is the one that defines the value. The value is generated inside CDS and
does not survive a CDS restart; nothing durable may be keyed on it.`,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			for _, spec := range specs {
				s, err := parseSecretSpec(spec)
				if err != nil {
					return err
				}
				cfg.Secrets = append(cfg.Secrets, s)
			}
			return run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.CDSURL, "cds-url", "", "https base URL of CDS")
	f.StringVar(&cfg.AttestationApiURL, "attestation-api-url", "", "local attestation-api used to verify CDS's RA-TLS certificate")
	f.StringSliceVar(&cfg.Measurements, "measurements", nil, "SHA-384 hex launch measurement(s) CDS must present (repeatable; empty pins none, UNSAFE)")
	f.StringVar(&cfg.CertPath, "cert", "/run/c8s/certs/tls.crt", "the pod's CDS-issued certificate, presented to CDS")
	f.StringVar(&cfg.KeyPath, "key", "/run/c8s/certs/tls.key", "private key for --cert")
	f.StringSliceVar(&specs, "secret", nil, "NAME=/store/path to fetch; NAME is the filename written under --out-dir (repeatable)")
	f.StringVar(&cfg.OutDir, "out-dir", "/run/c8s/secrets", "directory the secret files are written to; must be memory-backed")
	f.StringVar(&cfg.FileMode, "file-mode", "0640", "octal mode for the written files")
	f.IntVar(&cfg.Attempts, "attempts", 60, "how many times to try before failing; release is refused until every main container is running, so retries are expected")
	f.DurationVar(&cfg.RetryInterval, "retry-interval", 5*time.Second, "wait between attempts")
	f.DurationVar(&cfg.RequestTimeout, "request-timeout", 10*time.Second, "per-request timeout against CDS")
	f.DurationVar(&cfg.InventoryTimeout, "inventory-timeout", 5*time.Second, "timeout for redeeming a sandbox token from the node's admission inventory")
	return cmd
}
