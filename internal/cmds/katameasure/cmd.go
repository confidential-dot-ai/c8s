// Package katameasure implements `c8s kata measure`: the offline predictor for
// the SEV-SNP launch measurement of a kata-qemu-snp guest.
//
// Under --cvm-mode=pod every pod is its own CVM, and pods that differ in vCPU
// count have different launch digests, so there is no single fleet-wide value
// to pin. This command computes the digest for a given guest artifact and pod
// shape without booting anything, so per-workload measurement sets can be
// derived ahead of the install. See docs/kata-launch-measurement.md.
package katameasure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/confidential-dot-ai/c8s/pkg/snpmeasure"
)

type config struct {
	guestDir        string
	firmware        string
	vcpus           int
	podCPULimit     string
	defaultVCPUs    float64
	vcpuType        string
	cmdline         string
	kernelParams    string
	launchTimeout   int
	debugConsole    bool
	debugConsoleSet bool
	guestFeatures   uint64
	asJSON          bool
	verbose         bool
	skipVersion     bool
}

// Result is the --json document.
type Result struct {
	Measurement   string `json:"measurement"`
	VCPUs         int    `json:"vcpus"`
	VCPUType      string `json:"vcpuType"`
	VCPUSignature string `json:"vcpuSignature"`
	GuestFeatures uint64 `json:"guestFeatures"`
	Cmdline       string `json:"cmdline"`
	FirmwarePath  string `json:"firmwarePath"`
	FirmwareSHA   string `json:"firmwareSha256"`
	KernelPath    string `json:"kernelPath"`
	KernelSHA     string `json:"kernelSha256"`
	KataVersion   string `json:"kataVersion"`
	BuildVariant  string `json:"buildVariant"`
}

// NewCmd returns the `kata` command group with its `measure` subcommand.
func NewCmd() *cobra.Command {
	kata := &cobra.Command{
		Use:   "kata",
		Short: "Offline tooling for the kata confidential guest",
	}
	kata.AddCommand(newMeasureCmd())
	return kata
}

func newMeasureCmd() *cobra.Command {
	cfg := config{
		guestDir:      DefaultGuestDir,
		firmware:      DefaultFirmware,
		defaultVCPUs:  1,
		vcpuType:      DefaultVCPUType,
		kernelParams:  DefaultKernelParams,
		launchTimeout: DefaultLaunchProcessTimeout,
		guestFeatures: 1,
	}
	cmd := &cobra.Command{
		Use:   "measure",
		Short: "Compute the expected SEV-SNP launch measurement of a kata guest",
		Long: `measure predicts the SEV-SNP launch digest of a kata-qemu-snp guest from
the guest image artifacts and a pod's vCPU count, without booting the pod.

Under --cvm-mode=pod each pod is its own CVM. The launch digest covers the
OVMF image, the kernel/initrd/cmdline hash table QEMU builds for
kernel-hashes=on, and one VMSA page per vCPU — so pods that differ in vCPU
count measure differently and need separate values in cds.measurements.

The kernel command line is reassembled the way kata ` + SupportedKataVersion + ` builds it;
pass --cmdline to measure an exact captured line instead. Output is the bare
hex digest, one per line, ready for 'c8s verify --measurements-file'.

    c8s kata measure --vcpus 1
    c8s kata measure --guest-dir ./output --pod-cpu-limit 500m --json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.debugConsoleSet = cmd.Flags().Changed("debug-console")
			return run(cfg, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.guestDir, "guest-dir", cfg.guestDir, "kata-guest-base artifact directory (manifest.json + vmlinuz)")
	f.StringVar(&cfg.firmware, "firmware", cfg.firmware, "OVMF image kata boots the guest with")
	f.IntVar(&cfg.vcpus, "vcpus", 0, "guest vCPU count; required unless --pod-cpu-limit is given")
	f.StringVar(&cfg.podCPULimit, "pod-cpu-limit", "", "derive --vcpus from a pod's total CPU limit (e.g. 500m); unset means the pod has no CPU limit")
	f.Float64Var(&cfg.defaultVCPUs, "default-vcpus", cfg.defaultVCPUs, "hypervisor default_vcpus, the base kata adds --pod-cpu-limit to")
	f.StringVar(&cfg.vcpuType, "vcpu-type", cfg.vcpuType, "QEMU -cpu model the guest launches with")
	f.StringVar(&cfg.cmdline, "cmdline", "", "exact kernel command line to measure, bypassing derivation")
	f.StringVar(&cfg.kernelParams, "kernel-params", cfg.kernelParams, "hypervisor kernel_params, appended to the derived command line")
	f.IntVar(&cfg.launchTimeout, "launch-process-timeout", cfg.launchTimeout, "agent launch_process_timeout; 0 omits the parameter")
	f.BoolVar(&cfg.debugConsole, "debug-console", false, "agent debug_console_enabled (default: on for a -debug guest variant)")
	f.Uint64Var(&cfg.guestFeatures, "guest-features", cfg.guestFeatures, "VMSA SEV_FEATURES value (0x1 = SNPActive)")
	f.BoolVar(&cfg.asJSON, "json", false, "emit a JSON document instead of the bare digest")
	f.BoolVarP(&cfg.verbose, "verbose", "v", false, "print the derived inputs to stderr")
	f.BoolVar(&cfg.skipVersion, "skip-version-check", false, "measure a guest built against an unsupported kata version anyway")
	return cmd
}

func run(cfg config, stdout, stderr io.Writer) error {
	guest, err := LoadGuest(cfg.guestDir)
	if err != nil {
		return err
	}
	if guest.Manifest.KataVersion != SupportedKataVersion && !cfg.skipVersion && cfg.cmdline == "" {
		return fmt.Errorf("guest was built for kata %s but command-line derivation is pinned to %s; "+
			"pass --cmdline with the exact line, or --skip-version-check",
			guest.Manifest.KataVersion, SupportedKataVersion)
	}

	vcpus, err := resolveVCPUs(cfg)
	if err != nil {
		return err
	}

	cmdline := cfg.cmdline
	if cmdline == "" {
		debug := guest.DebugVariant()
		if cfg.debugConsoleSet {
			debug = cfg.debugConsole
		}
		if cmdline, err = Cmdline(CmdlineParams{
			VCPUs:                vcpus,
			VerityParams:         guest.VerityParams,
			RootfsType:           guest.RootfsType,
			DebugConsole:         debug,
			LaunchProcessTimeout: cfg.launchTimeout,
			KernelParams:         cfg.kernelParams,
		}); err != nil {
			return err
		}
	}

	sig, err := snpmeasure.VCPUSignatureByName(cfg.vcpuType)
	if err != nil {
		return err
	}
	firmware, err := os.ReadFile(cfg.firmware)
	if err != nil {
		return fmt.Errorf("read firmware: %w", err)
	}
	hashes, err := snpmeasure.KernelHashesFromFiles(guest.KernelPath, "", cmdline)
	if err != nil {
		return err
	}
	if err := guest.VerifyKernel(hex.EncodeToString(hashes.Kernel[:])); err != nil {
		return err
	}
	ld, err := snpmeasure.LaunchDigest(snpmeasure.Config{
		Firmware:      firmware,
		KernelHashes:  hashes,
		VCPUs:         vcpus,
		VCPUSig:       sig,
		GuestFeatures: cfg.guestFeatures,
	})
	if err != nil {
		return err
	}

	res := Result{
		Measurement:   hex.EncodeToString(ld),
		VCPUs:         vcpus,
		VCPUType:      cfg.vcpuType,
		VCPUSignature: fmt.Sprintf("%#x", sig),
		GuestFeatures: cfg.guestFeatures,
		Cmdline:       cmdline,
		FirmwarePath:  cfg.firmware,
		FirmwareSHA:   hex.EncodeToString(sha256sum(firmware)),
		KernelPath:    guest.KernelPath,
		KernelSHA:     hex.EncodeToString(hashes.Kernel[:]),
		KataVersion:   guest.Manifest.KataVersion,
		BuildVariant:  guest.Manifest.BuildVariant,
	}
	if cfg.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if cfg.verbose {
		fmt.Fprintf(stderr, "kata:     %s (%s)\n", res.KataVersion, res.BuildVariant)
		fmt.Fprintf(stderr, "firmware: %s sha256=%s\n", res.FirmwarePath, res.FirmwareSHA)
		fmt.Fprintf(stderr, "kernel:   %s sha256=%s\n", res.KernelPath, res.KernelSHA)
		fmt.Fprintf(stderr, "vcpus:    %d (%s %s)\n", res.VCPUs, res.VCPUType, res.VCPUSignature)
		fmt.Fprintf(stderr, "cmdline:  %s\n", res.Cmdline)
	}
	fmt.Fprintln(stdout, res.Measurement)
	return nil
}

func resolveVCPUs(cfg config) (int, error) {
	if cfg.vcpus > 0 {
		return cfg.vcpus, nil
	}
	if cfg.vcpus < 0 {
		return 0, fmt.Errorf("--vcpus must be > 0, got %d", cfg.vcpus)
	}
	if cfg.podCPULimit == "" {
		return 0, fmt.Errorf("one of --vcpus or --pod-cpu-limit is required")
	}
	q, err := resource.ParseQuantity(cfg.podCPULimit)
	if err != nil {
		return 0, fmt.Errorf("--pod-cpu-limit: %w", err)
	}
	return VCPUsForPod(cfg.defaultVCPUs, q.AsApproximateFloat64())
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
