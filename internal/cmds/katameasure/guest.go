package katameasure

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// ManifestVersion is the manifest.json schema this tool reads.
const ManifestVersion = 2

// DefaultGuestDir is where the c8s-kata-image-puller DaemonSet lands the
// published kata-guest-base artifact on every node.
const DefaultGuestDir = "/var/lib/c8s/kata-images/base"

// DefaultFirmware is the OVMF build kata-qemu-snp boots (the `firmware` key of
// configuration-qemu-snp.toml).
const DefaultFirmware = "/opt/kata/share/ovmf/AMDSEV.fd"

// DefaultVCPUType is the QEMU CPU model kata launches SNP guests with.
const DefaultVCPUType = "EPYC-v4"

// Manifest is the subset of kata-guest-base's manifest.json that determines the
// launch measurement.
type Manifest struct {
	Version            int    `json:"version"`
	BootModel          string `json:"boot_model"`
	KataVersion        string `json:"kata_version"`
	RootfsType         string `json:"rootfs_type"`
	BuildVariant       string `json:"build_variant"`
	KernelVerityParams string `json:"kernel_verity_params"`
	Outputs            struct {
		Kernel struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"kernel"`
	} `json:"outputs"`
}

// bootModelDirectKernel is the only boot model this tool can measure; an IGVM
// or UKI guest is measured from the IGVM file, not from these inputs.
const bootModelDirectKernel = "kata-direct-kernel"

// Guest is a loaded kata-guest-base artifact directory.
type Guest struct {
	Dir        string
	Manifest   Manifest
	KernelPath string
	// VerityParams and RootfsType come from the sidecar files when present,
	// because those — not manifest.json — are what the puller copies into the
	// kata config that produces the measured command line.
	VerityParams string
	RootfsType   string
}

// LoadGuest reads a guest artifact directory as laid down by the puller.
func LoadGuest(dir string) (*Guest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read guest manifest: %w", err)
	}
	g := &Guest{Dir: dir}
	if err := json.Unmarshal(raw, &g.Manifest); err != nil {
		return nil, fmt.Errorf("parse guest manifest: %w", err)
	}
	if g.Manifest.Version != ManifestVersion {
		return nil, fmt.Errorf("guest manifest is version %d, this tool reads version %d",
			g.Manifest.Version, ManifestVersion)
	}
	if g.Manifest.BootModel != bootModelDirectKernel {
		return nil, fmt.Errorf("guest boot_model is %q, want %q", g.Manifest.BootModel, bootModelDirectKernel)
	}
	kernel := g.Manifest.Outputs.Kernel.Path
	if kernel == "" {
		kernel = "vmlinuz"
	}
	g.KernelPath = filepath.Join(dir, kernel)
	if _, err := os.Stat(g.KernelPath); err != nil {
		return nil, fmt.Errorf("guest kernel: %w", err)
	}

	g.VerityParams = sidecar(dir, "kernel_verity_params", g.Manifest.KernelVerityParams)
	g.RootfsType = sidecar(dir, "rootfs_type", g.Manifest.RootfsType)
	if g.RootfsType == "" {
		g.RootfsType = "ext4" // the puller's own fallback
	}
	return g, nil
}

// sidecar reads one of the puller's plain-text artifact files, falling back to
// the manifest's mirror of the same value.
func sidecar(dir, name, fallback string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return fallback
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v
	}
	return fallback
}

// VerifyKernel reports whether the kernel on disk matches the sha256 the build
// recorded. A mismatch means the artifact directory is not the one the manifest
// describes, so any digest derived from it would be a wrong pin.
func (g *Guest) VerifyKernel(gotSHA256 string) error {
	want := g.Manifest.Outputs.Kernel.SHA256
	if want == "" || strings.EqualFold(want, gotSHA256) {
		return nil
	}
	return fmt.Errorf("kernel %s has sha256 %s but manifest.json records %s",
		g.KernelPath, gotSHA256, want)
}

// DebugVariant reports whether this is the -debug build. The chart ties
// kata.guestImage.debug to both the image tag and the guest agent's debug
// console, so the variant name predicts the command line.
func (g *Guest) DebugVariant() bool {
	return strings.HasSuffix(g.Manifest.BuildVariant, "-debug")
}

// VCPUsForPod returns the vCPU count kata gives a pod whose containers request
// cpuLimitCores in total, under static_sandbox_resource_mgmt. kata adds the
// workload's CPU limit to default_vcpus and rounds up; a pod where any
// container has no CPU limit contributes nothing, because containerd reports an
// unbounded sandbox quota. See docs/kata-launch-measurement.md.
func VCPUsForPod(defaultVCPUs float64, cpuLimitCores float64) (int, error) {
	if defaultVCPUs <= 0 {
		return 0, fmt.Errorf("default_vcpus must be > 0, got %v", defaultVCPUs)
	}
	if cpuLimitCores < 0 {
		return 0, fmt.Errorf("cpu limit must be >= 0, got %v", cpuLimitCores)
	}
	return int(math.Ceil(defaultVCPUs + cpuLimitCores)), nil
}
