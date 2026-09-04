// Package policymeasure implements `c8s policy-measure`, the measured
// c8s-policy-measure.service that runs on every node boot before RKE2 and
// commits the boot's policy mode to RTMR[3]: ModeDynamic on a boot without
// a policydata disk, ModeStatic followed by the policy event on a boot with
// one. The mode is explicit and written to <policy-dir>/mode last, so every
// static consumer (cred-release, the NRI plugin, CDS) reads a mode the
// register already commits to and never infers one from a file's presence.
package policymeasure

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

// Launch disks and the staged key. The unit passes none of them, so the
// binary defaults are the contract; the policy directory itself is
// policybundle.DefaultPolicyDir, shared with every reader.
const (
	// DefaultOpkeyDisk is the operator-key launch ISO; its presence on a
	// static boot is fatal.
	DefaultOpkeyDisk = "/dev/disk/by-label/opkeydata"
	// DefaultPolicyDisk is the policy bundle launch ISO.
	DefaultPolicyDisk = "/dev/disk/by-label/policydata"
	// DefaultOperatorPubkey is the initrd-staged operator key every
	// dynamic-boot reader shares.
	DefaultOperatorPubkey = policybundle.OperatorPubkeyPath
)

// Config is the measurer's input.
type Config struct {
	// Platform is the TEE platform ("tdx" or "snp"). Only TDX has a runtime
	// register; SNP boots are always dynamic.
	Platform string
	// PolicyDir receives mode, digest and the members.
	PolicyDir string
	// OpkeyDisk and PolicyDisk are the launch ISOs, by label.
	OpkeyDisk  string
	PolicyDisk string
	// OperatorPubkey is the initrd-staged operator key, if any.
	OperatorPubkey string
}

// NewCmd builds the `policy-measure` subcommand. It is run by the node
// image's c8s-policy-measure.service, whose FailureAction powers the node
// off on any non-zero exit.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "policy-measure",
		Short: "Commit the boot's policy mode (and static allowlist bundle) to RTMR[3]",
		Long: "policy-measure runs once per boot, before containerd, and extends\n" +
			"the policy mode event into TDX RTMR[3]. Without a policydata disk it\n" +
			"extends ModeDynamic and writes mode=dynamic. With one it refuses an\n" +
			"operator key, reads the bundle read-only, lints static-allowlist.json\n" +
			"as a sealed document, publishes the members and their index digest\n" +
			"under --policy-dir, extends ModeStatic and the policy event, checks\n" +
			"the register reads back as ForStaticAllowlist(index), and writes\n" +
			"mode=static last. Any failure exits non-zero.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return Run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.PolicyDir, "policy-dir", policybundle.DefaultPolicyDir, "tmpfs directory that receives mode, digest and the bundle members")
	f.StringVar(&cfg.OpkeyDisk, "opkey-disk", DefaultOpkeyDisk, "operator-key launch ISO; fatal when present on a static boot")
	f.StringVar(&cfg.PolicyDisk, "policy-disk", DefaultPolicyDisk, "policy bundle launch ISO; absent means a dynamic boot")
	f.StringVar(&cfg.OperatorPubkey, "operator-pubkey", DefaultOperatorPubkey, "initrd-staged operator public key; its RTMR[3] seed must match the register")
	// No default: the baked unit always passes the flag explicitly.
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}
