// Package katameasure implements `c8s kata measure`: the offline predictor for
// a kata confidential guest's launch measurement, on SEV-SNP and on TDX.
//
// On SNP, under --cvm-mode=pod every pod is its own CVM and pods that differ in
// vCPU count have different launch digests, so there is no single fleet-wide
// value to pin; this command computes the digest for a given guest artifact and
// pod shape without booting anything. On TDX the pinned value is MRTD, which
// covers the TDVF image alone — one value covers the fleet.
// See docs/kata-launch-measurement.md.
package katameasure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/confidential-dot-ai/c8s/pkg/snpmeasure"
	"github.com/confidential-dot-ai/c8s/pkg/tdxmeasure"
)

type config struct {
	platform        string
	platformFrom    string
	firmwareSet     bool
	guestDir        string
	firmware        string
	kataConfigDir   string
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

// Result is the --json document. The SNP-only fields are omitted on TDX, whose
// MRTD is a function of the firmware alone.
type Result struct {
	Platform string `json:"platform"`
	// PlatformFrom is the node evidence that chose Platform; empty when
	// --platform did.
	PlatformFrom  string `json:"platformDetectedFrom,omitempty"`
	Measurement   string `json:"measurement"`
	VCPUs         int    `json:"vcpus,omitempty"`
	VCPUType      string `json:"vcpuType,omitempty"`
	VCPUSignature string `json:"vcpuSignature,omitempty"`
	GuestFeatures uint64 `json:"guestFeatures,omitempty"`
	Cmdline       string `json:"cmdline,omitempty"`
	FirmwarePath  string `json:"firmwarePath"`
	FirmwareSHA   string `json:"firmwareSha256"`
	KernelPath    string `json:"kernelPath,omitempty"`
	KernelSHA     string `json:"kernelSha256,omitempty"`
	KataVersion   string `json:"kataVersion,omitempty"`
	BuildVariant  string `json:"buildVariant,omitempty"`
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
		kataConfigDir: DefaultKataConfigDir,
		defaultVCPUs:  1,
		vcpuType:      DefaultVCPUType,
		kernelParams:  DefaultKernelParams,
		launchTimeout: DefaultLaunchProcessTimeout,
		guestFeatures: 1,
	}
	cmd := &cobra.Command{
		Use:   "measure",
		Short: "Compute the expected launch measurement of a kata guest",
		Long: `measure predicts a kata confidential guest's launch measurement from the
guest image artifacts, without booting the pod.

--platform defaults to the TEE this node reports — the kata shim carrying
c8s's config.d drop-in, else /sys/module/kvm_intel/parameters/tdx — and to
snp when the node reports neither. An explicit --platform always wins; -v
and --json name the platform measured and what chose it.

--platform snp computes the SEV-SNP launch digest of a
kata-qemu-snp guest. Under --cvm-mode=pod each pod is its own CVM. The
digest covers the OVMF image, the kernel/initrd/cmdline hash table QEMU
builds for kernel-hashes=on, and one VMSA page per vCPU — so pods that
differ in vCPU count measure differently and need separate values in
cds.measurements. The kernel command line is reassembled the way kata ` + SupportedKataVersion + `
builds it; pass --cmdline to measure an exact captured line instead.

--platform tdx computes the Intel TDX MRTD of a kata-qemu-tdx guest. MRTD
covers the TDVF image alone: the guest kernel, command line, vCPU count and
RAM size are measured into RTMR[0..2], which c8s does not pin. One MRTD
therefore covers every pod shape, and the pod-shape flags are rejected.

Output is the bare hex digest, one per line, ready for
'c8s verify --measurements-file'.

    c8s kata measure --vcpus 1
    c8s kata measure --guest-dir ./output --pod-cpu-limit 500m --json
    c8s kata measure --platform tdx`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.debugConsoleSet = cmd.Flags().Changed("debug-console")
			cfg.firmwareSet = cmd.Flags().Changed("firmware")
			return run(cfg, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.platform, "platform", "", "TEE platform to measure: snp (SEV-SNP launch digest) or tdx (MRTD) (default: this node's detected TEE, else snp)")
	f.StringVar(&cfg.guestDir, "guest-dir", cfg.guestDir, "kata-guest-base artifact directory (manifest.json + vmlinuz)")
	f.StringVar(&cfg.firmware, "firmware", cfg.firmware, "firmware image kata boots the guest with (default "+DefaultTDXFirmware+" under --platform tdx)")
	f.StringVar(&cfg.kataConfigDir, "kata-config-dir", cfg.kataConfigDir, "kata-deploy config root, read to detect this node's TEE; empty skips detection")
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

// Platforms `measure` can compute a launch measurement for. These match the
// pkg/types.Platform spellings the CDS allow-list and RA-TLS policy use.
const (
	platformSNP = "snp"
	platformTDX = "tdx"
)

func run(cfg config, stdout, stderr io.Writer) error {
	cfg.platform, cfg.platformFrom = resolvePlatform(cfg)
	switch cfg.platform {
	case platformSNP:
		return runSNP(cfg, stdout, stderr)
	case platformTDX:
		return runTDX(cfg, stdout, stderr)
	default:
		return fmt.Errorf("--platform must be %q or %q, got %q", platformSNP, platformTDX, cfg.platform)
	}
}

// resolvePlatform picks what to measure. An unset --platform hands the choice
// to the node, because kata-static installs AMDSEV.fd on TDX nodes too and an
// unnoticed SNP default there measures firmware nothing will ever boot. A node
// that reports nothing keeps the historical snp default.
func resolvePlatform(cfg config) (platform, from string) {
	if cfg.platform != "" {
		return cfg.platform, ""
	}
	if p, ev := detectPlatform(cfg.kataConfigDir); p != "" {
		return p, ev
	}
	return platformSNP, ""
}

// detectedNote annotates a platform the node chose rather than the flag.
func detectedNote(from string) string {
	if from == "" {
		return ""
	}
	return " (detected from " + from + ")"
}

// runTDX computes MRTD. It deliberately reads no guest artifacts: MRTD covers
// the TDVF image only. Flags that shape a pod are rejected rather than ignored,
// so a caller who thinks they are pinning a per-shape value finds out here.
func runTDX(cfg config, stdout, stderr io.Writer) error {
	if err := rejectSNPOnlyFlags(cfg); err != nil {
		return err
	}
	path := cfg.firmware
	if !cfg.firmwareSet {
		path = DefaultTDXFirmware
	}
	firmware, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read firmware: %w", err)
	}
	mrtd, err := tdxmeasure.MRTD(firmware)
	if err != nil {
		return err
	}
	res := Result{
		Platform:     platformTDX,
		PlatformFrom: cfg.platformFrom,
		Measurement:  hex.EncodeToString(mrtd),
		FirmwarePath: path,
		FirmwareSHA:  hex.EncodeToString(sha256sum(firmware)),
	}
	if cfg.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if cfg.verbose {
		fmt.Fprintf(stderr, "platform: %s (MRTD)%s\n", res.Platform, detectedNote(res.PlatformFrom))
		fmt.Fprintf(stderr, "firmware: %s sha256=%s\n", res.FirmwarePath, res.FirmwareSHA)
		fmt.Fprintf(stderr, "note:     covers TDVF only; kernel/cmdline/vCPUs measure into RTMRs\n")
	}
	fmt.Fprintln(stdout, res.Measurement)
	return nil
}

// rejectSNPOnlyFlags fails on inputs that only shape an SNP digest.
func rejectSNPOnlyFlags(cfg config) error {
	var set []string
	if cfg.vcpus != 0 {
		set = append(set, "--vcpus")
	}
	if cfg.podCPULimit != "" {
		set = append(set, "--pod-cpu-limit")
	}
	if cfg.cmdline != "" {
		set = append(set, "--cmdline")
	}
	if cfg.debugConsoleSet {
		set = append(set, "--debug-console")
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("not valid when measuring tdx%s: %s. Those shape the SNP launch digest only; "+
		"TDX MRTD covers the TDVF image alone (vCPUs, kernel and command line measure into RTMRs, "+
		"which c8s does not pin)", detectedNote(cfg.platformFrom), strings.Join(set, ", "))
}

func runSNP(cfg config, stdout, stderr io.Writer) error {
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
		FirmwarePath:  cfg.firmware,
		KernelHashes:  hashes,
		VCPUs:         vcpus,
		VCPUSig:       sig,
		GuestFeatures: cfg.guestFeatures,
	})
	if err != nil {
		return err
	}

	res := Result{
		Platform:      platformSNP,
		PlatformFrom:  cfg.platformFrom,
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
		fmt.Fprintf(stderr, "platform: %s (launch digest)%s\n", res.Platform, detectedNote(res.PlatformFrom))
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
