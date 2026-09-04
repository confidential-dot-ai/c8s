package katameasure

import (
	"fmt"
	"strconv"
	"strings"
)

// SupportedKataVersion is the kata release whose command-line assembly Cmdline
// reproduces. A guest built against another release must be measured with an
// explicitly supplied --cmdline. Bump this together with the kata-deploy pin in
// internal/helmchart/pod/values.yaml, and re-check the golden cmdlines in
// testdata/.
const SupportedKataVersion = "3.30.0"

// Fixed kata 3.30.0 kernel-parameter groups, in the order
// (*qemu).kernelParameters emits them. Sources, in emission order:
//
//	baseParams    virtcontainers/qemu_amd64.go   kernelParams
//	consoleParams virtcontainers/qemu_arch_base.go appendConsole
//	quietParams   virtcontainers/qemu_arch_base.go kernelParamsNonDebug + kernelParamsSystemdNonDebug
//	agentParams   virtcontainers/kata_agent.go   the sandbox/agent block
const (
	baseParams    = "tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0"
	consoleParams = "console=hvc0 console=hvc1"
	quietParams   = "quiet systemd.show_status=false"
	agentParams   = "systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket scsi_mod.scan=none"

	// DefaultKernelParams is the qemu-snp config's kernel_params, which the
	// c8s puller drop-in re-emits verbatim.
	DefaultKernelParams = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"

	// DefaultLaunchProcessTimeout is the qemu-snp config's launch_process_timeout.
	DefaultLaunchProcessTimeout = 6

	// debugConsoleVPort is kata's fixed vsock port for the guest debug console.
	debugConsoleVPort = 1026
)

// CmdlineParams are the inputs that vary between c8s kata-qemu-snp guests.
// Everything else in the command line is fixed by kata SupportedKataVersion and
// the shipped configuration-qemu-snp.toml.
type CmdlineParams struct {
	// VCPUs is the guest vCPU count. It reaches the digest twice: as nr_cpus
	// here, and as the number of measured VMSA pages.
	VCPUs int
	// VerityParams is the guest image's kernel_verity_params line.
	VerityParams string
	// RootfsType is the guest rootfs filesystem, e.g. "ext4".
	RootfsType string
	// DebugConsole mirrors [agent.kata] debug_console_enabled, which the puller
	// drop-in ties to kata.guestImage.debug.
	DebugConsole bool
	// LaunchProcessTimeout mirrors [agent.kata] launch_process_timeout.
	LaunchProcessTimeout int
	// KernelParams is the [hypervisor.qemu] kernel_params value, appended last.
	KernelParams string
}

// Cmdline reproduces the kernel command line kata passes to qemu -append, which
// QEMU hashes into the launch measurement when kernel-hashes=on.
func Cmdline(p CmdlineParams) (string, error) {
	if p.VCPUs < 1 {
		return "", fmt.Errorf("vcpus must be >= 1, got %d", p.VCPUs)
	}
	root, err := verityRootParams(p.VerityParams, p.RootfsType)
	if err != nil {
		return "", err
	}
	parts := []string{
		baseParams,
		root,
		consoleParams,
		quietParams,
		"panic=1",
		"nr_cpus=" + strconv.Itoa(p.VCPUs),
		"selinux=0",
		agentParams,
	}
	if p.DebugConsole {
		parts = append(parts, fmt.Sprintf("agent.debug_console agent.debug_console_vport=%d", debugConsoleVPort))
	}
	if p.LaunchProcessTimeout > 0 {
		parts = append(parts, fmt.Sprintf("agent.launch_process_timeout=%d", p.LaunchProcessTimeout))
	}
	if p.KernelParams != "" {
		parts = append(parts, p.KernelParams)
	}
	return strings.Join(parts, " "), nil
}

// verityRootParams renders kata's GetKernelRootParams for a dm-verity rootfs on
// virtio-blk (SNP guests get no nvdimm, so vda1/vda2 rather than pmem0p1/p2).
func verityRootParams(verityParams, rootfsType string) (string, error) {
	v, err := parseVerityParams(verityParams)
	if err != nil {
		return "", err
	}
	rootFlags, ok := map[string]string{
		"ext4":  "data=ordered,errors=remount-ro ro",
		"xfs":   "ro",
		"erofs": "ro",
	}[rootfsType]
	if !ok {
		return "", fmt.Errorf("unsupported rootfs type %q", rootfsType)
	}
	sectors := v.dataBlockSize / 512 * v.dataBlocks
	return fmt.Sprintf(
		`dm-mod.create="dm-verity,,,ro,0 %d verity 1 /dev/vda1 /dev/vda2 %d %d %d 0 sha256 %s %s" `+
			`root=/dev/dm-0 rootflags=%s rootfstype=%s`,
		sectors, v.dataBlockSize, v.hashBlockSize, v.dataBlocks, v.rootHash, v.salt,
		rootFlags, rootfsType), nil
}

type verityConfig struct {
	rootHash      string
	salt          string
	dataBlocks    uint64
	dataBlockSize uint64
	hashBlockSize uint64
}

func parseVerityParams(s string) (verityConfig, error) {
	var v verityConfig
	if s == "" {
		return v, fmt.Errorf("empty kernel_verity_params")
	}
	seen := map[string]bool{}
	for _, kv := range strings.Split(s, ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			return v, fmt.Errorf("malformed kernel_verity_params entry %q", kv)
		}
		var num *uint64
		switch key {
		case "root_hash":
			v.rootHash = val
		case "salt":
			v.salt = val
		case "data_blocks":
			num = &v.dataBlocks
		case "data_block_size":
			num = &v.dataBlockSize
		case "hash_block_size":
			num = &v.hashBlockSize
		default:
			return v, fmt.Errorf("unknown kernel_verity_params key %q", key)
		}
		if num != nil {
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return v, fmt.Errorf("kernel_verity_params %s=%q: %w", key, val, err)
			}
			*num = n
		}
		seen[key] = true
	}
	for _, k := range []string{"root_hash", "salt", "data_blocks", "data_block_size", "hash_block_size"} {
		if !seen[k] {
			return v, fmt.Errorf("kernel_verity_params is missing %s", k)
		}
	}
	if v.dataBlockSize == 0 || v.dataBlockSize%512 != 0 {
		return v, fmt.Errorf("data_block_size %d is not a multiple of 512", v.dataBlockSize)
	}
	return v, nil
}
