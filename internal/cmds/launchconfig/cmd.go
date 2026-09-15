package launchconfig

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

// NewCmd returns the authenticated launch configuration command group: the
// operator-side bundle generator and the guest-side stage.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "launch-config", Short: "Create, extend and stage a measured node's signed launch configuration"}
	cmd.AddCommand(newBundleCmd(), newAddFollowerCmd(), newStageCmd())
	return cmd
}

func newBundleCmd() *cobra.Command {
	var opts BundleOptions
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a cluster's launch bundle: keys, tokens and signed leader/follower documents",
		Long: `Create everything one cluster needs to boot from the measured node image:
a leader launch key and a follower launch key, fresh RKE2 join tokens, a
signed launch.yaml per node and the client policy that pins the leader.

  <out>/leader.key     leader launch key; also the operator key for
                       'c8s get-kubeconfig --operator-key' and signed CDS writes
  <out>/follower.key   the follower launch key; 'add-follower' reuses it
  <out>/leader.json    C8S_MEASUREMENTS_CONFIG for clients of this cluster
  <out>/leader/        pubkey, launch.yaml, launch.yaml.sig: the leader's opkeydata
  <out>/<follower>/    the same three files for each --follower

Attach each node directory as its opkeydata disk (an ISO labelled opkeydata,
or a KubeVirt Secret volume with volumeLabel opkeydata). On SNP, also set
HOST_DATA to SHA-256 of that node's pubkey file. See docs/operator.md,
"Authenticated launch configuration".`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := NewBundle(opts); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote launch bundle %s: %s", opts.Dir, filepath.Join(opts.Dir, leaderDir))
			for _, name := range opts.Followers {
				fmt.Fprintf(cmd.OutOrStdout(), ", %s", filepath.Join(opts.Dir, name))
			}
			fmt.Fprintf(cmd.OutOrStdout(), " (private keys: %s, %s)\n",
				filepath.Join(opts.Dir, leaderKeyFile), filepath.Join(opts.Dir, followerKeyFile))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "out", "", "bundle directory to create (must not exist)")
	f.StringVar(&opts.ClusterID, "cluster-id", "", "cluster name, an RFC1123 label")
	f.StringVar(&opts.ManifestPath, "image-manifest", "", "manifest.json published with the exact node image to boot")
	f.IntVar(&opts.VCPUs, "vcpus", 0, "SNP only: the VM's vCPU count, selecting its launch digest from the manifest")
	f.StringVar(&opts.LeaderName, "leader-name", "", "leader node name (default <cluster-id>-leader)")
	f.StringVar(&opts.LeaderAddress, "leader-address", "", "leader IPv4 address every node can reach; required with followers, otherwise the leader autodetects it")
	f.StringArrayVar(&opts.Followers, "follower", nil, "follower node name; repeatable")
	f.StringVar(&opts.TLSSAN, "tls-san", "", "DNS name for the front-door certificate (default c8s.local)")
	f.StringVar(&opts.WorkloadsPath, "workloads", "", "optional c8s.allowlist/v1 JSON file applied as the initial workload allowlist")
	for _, name := range []string{"out", "cluster-id", "image-manifest"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newAddFollowerCmd() *cobra.Command {
	var dir, name, leaderAddress string
	cmd := &cobra.Command{
		Use:   "add-follower",
		Short: "Add a signed follower document to an existing launch bundle",
		Long: `Derive a follower launch.yaml from the bundle's leader document (same
cluster, image, agent token and keys, never the server token), sign it with
the bundle's follower key and write <bundle>/<name>. Nothing the leader
already booted with changes.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := AddFollower(dir, name, leaderAddress); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", filepath.Join(dir, name))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "bundle", "", "bundle directory created by 'launch-config new'")
	f.StringVar(&name, "name", "", "follower node name, an RFC1123 label")
	f.StringVar(&leaderAddress, "leader-address", "", "leader IPv4 address (default: the leader document's, which must then be explicit)")
	for _, flag := range []string{"bundle", "name"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

func newStageCmd() *cobra.Command {
	var cfg Config
	stage := &cobra.Command{
		Use: "stage", Short: "Verify signed launch configuration and stage the selected node role",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := Stage(cmd.Context(), cfg); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "authenticated launch configuration staged")
			return nil
		},
	}
	f := stage.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "image TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", DefaultAttestationAPIURL, "trusted node-local attestation API")
	f.StringVar(&cfg.DocumentPath, "config", "", "required signed launch.yaml")
	f.StringVar(&cfg.SignaturePath, "signature", "", "required detached launch.yaml.sig")
	for _, name := range []string{"platform", "config", "signature"} {
		_ = stage.MarkFlagRequired(name)
	}
	return stage
}
