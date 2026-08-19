package getkubeconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// NewCmd builds the `get-kubeconfig` subcommand: the operator-side client that
// obtains an admin kubeconfig from a measured TDX CVM by attesting the
// node, confirming it was launched to trust the operator's key (RTMR[3]), and
// exchanging a CSR for a signed client cert over the cred-release endpoint.
func NewCmd() *cobra.Command {
	var (
		cfg  Config
		node string
		vmi  string
	)
	cmd := &cobra.Command{
		Use:   "get-kubeconfig",
		Short: "Attest a c8s CVM and obtain an operator kubeconfig via the measured image + operator-key gate",
		Long: "get-kubeconfig attests a measured c8s TDX CVM and enforces its full\n" +
			"measured identity: the guest image tuple (MRTD, RTMR[1], RTMR[2]) from\n" +
			"an explicitly selected build-artifact manifest, plus the RTMR[3] chain\n" +
			"seeded by the operator's key and extended by the expected workload\n" +
			"images. It then exchanges a CSR for a short-lived kube client cert over\n" +
			"the cred-release endpoint and writes a kubeconfig. Verification runs\n" +
			"in-process (attestation-go).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.OperatorKeyPath == "" || cfg.ImageManifestPath == "" || cfg.OutPath == "" {
				return fmt.Errorf("--operator-key, --image-manifest and --out are required")
			}
			// --vmi resolves a KubeVirt guest to the address --node would have
			// been given; --node <host> is a convenience that fills the three
			// URLs with the standard ports. Explicit --attest-url/--release-url/
			// --apiserver-url override. At least one of vmi, node, or the
			// explicit URLs must be set.
			if vmi != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
				defer cancel()
				addr, err := resolveVMIAddress(ctx, vmi)
				if err != nil {
					return fmt.Errorf("resolve --vmi %q: %w", vmi, err)
				}
				node = addr
			}
			if node != "" {
				if cfg.AttestURL == "" {
					cfg.AttestURL = fmt.Sprintf("http://%s:8400/attest", node)
				}
				if cfg.ReleaseBaseURL == "" {
					cfg.ReleaseBaseURL = fmt.Sprintf("https://%s:8443", node)
				}
				if cfg.APIServerURL == "" {
					cfg.APIServerURL = fmt.Sprintf("https://%s:6443", node)
				}
			}
			if cfg.AttestURL == "" || cfg.ReleaseBaseURL == "" || cfg.APIServerURL == "" {
				return fmt.Errorf("set --node or --vmi, or all of --attest-url/--release-url/--apiserver-url")
			}
			return Run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&node, "node", "", "guest host/IP; fills --attest-url/--release-url/--apiserver-url with standard ports (8400/8443/6443)")
	f.StringVar(&vmi, "vmi", "", "guest as KubeVirt VMI [namespace/]name; resolves its address through the current kubeconfig and uses it as --node (namespace defaults to the kubeconfig context's)")
	f.StringVar(&cfg.AttestURL, "attest-url", "", "attestation-api /attest URL (overrides --node)")
	f.StringVar(&cfg.ReleaseBaseURL, "release-url", "", "cred-release base URL (overrides --node)")
	f.StringVar(&cfg.APIServerURL, "apiserver-url", "", "apiserver URL for the kubeconfig (overrides --node)")
	f.StringVar(&cfg.OperatorKeyPath, "operator-key", "", "operator ECDSA private key PEM (its public half is bound into RTMR[3]) (required)")
	f.StringVar(&cfg.ImageManifestPath, "image-manifest", "", "an explicitly selected, provenanced build-artifact manifest carrying the expected guest image's measured identity — TDX: the full tuple (mrtd, rtmr1, rtmr2); SNP: the per-SMP launch digests (snp_variants). The manifest's shape selects the platform, and the gate pins every value, so a host cannot substitute the guest image and replay the operator-key binding (required)")
	f.StringArrayVar(&cfg.WorkloadImages, "workload-image", nil, "digest-pinned image ref (\"sha256:<hex>\" or \"name@sha256:<hex>\"; tags rejected) the node's measurer is expected to have extended into RTMR[3]; repeatable, in first-extend order. Omit if the node runs no measured workloads. TDX only — SNP has no runtime-extend register")
	f.StringVar(&cfg.ContextName, "context", "c8s", "kubeconfig cluster/context/user name")
	f.StringVar(&cfg.TLSServerName, "tls-server-name", "c8s-cvm", "kubeconfig tls-server-name — pins apiserver cert verification to this SAN (the image bakes it into tls-san) instead of the dialed IP. Empty to omit")
	f.StringVar(&cfg.OutPath, "out", "", "output kubeconfig path (required)")
	f.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "per-step network timeout")
	cmd.MarkFlagsMutuallyExclusive("node", "vmi")
	return cmd
}
