package getvolume

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// NewCmd returns the cobra subcommand. Registered as a child of `c8s`.
func NewCmd() *cobra.Command {
	var (
		cfg   config
		specs []string
	)
	cmd := &cobra.Command{
		Use:   "get-volume",
		Short: "Fetch this pod's volume keys from CDS and have the node open them",
		Long: `get-volume fetches the key for each encrypted volume a workload is granted
and hands it to the node agent, which opens the device and mounts it read-only
into this pod.

It authenticates with the pod's CDS-issued certificate and a sandbox token
redeemed from the node's admission inventory, and CDS releases only when the
containers running in the sandbox match a workload entry holding a grant for
the requested path. That is only true once every main container is running, so
early attempts are refused and get-volume retries — the volume appears shortly
after the workload starts, and a consumer must wait for it.

The key must already be in the store, put there by ` + "`c8s volume create`" + `.
Nothing here creates one.`,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			for _, spec := range specs {
				v, err := parseVolumeSpec(spec)
				if err != nil {
					return err
				}
				cfg.Volumes = append(cfg.Volumes, v)
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
	f.StringSliceVar(&specs, "volume", nil, "NAME=/store/path to open; NAME selects the device by serial (repeatable)")
	f.StringVar(&cfg.SocketDir, "socket-dir", workloadclaims.SidecarSocketDir, "directory holding the node agent's socket, as this pod sees it")
	f.BoolVar(&cfg.WorkloadClaimsGuest, "workload-claims-guest", false, "Reach the inventory and the volume daemon on the kata guest's loopback addresses instead of node-CVM Unix sockets. Both shapes are compiled in; this only selects which applies, so a wrong setting fails closed rather than redirecting the request")
	f.IntVar(&cfg.Attempts, "attempts", 60, "how many times to try before failing; release is refused until every main container is running, so retries are expected")
	f.DurationVar(&cfg.RetryInterval, "retry-interval", 5*time.Second, "wait between attempts")
	f.DurationVar(&cfg.RequestTimeout, "request-timeout", 10*time.Second, "per-request timeout against CDS and the node agent")
	f.DurationVar(&cfg.InventoryTimeout, "inventory-timeout", 5*time.Second, "timeout for redeeming a sandbox token from the node's admission inventory")
	return cmd
}
