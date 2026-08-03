package katameasure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultKataConfigDir is kata-deploy's config root: one runtimes/<shim>/
// directory per hypervisor shim, each with its own config.d.
const DefaultKataConfigDir = "/opt/kata/share/defaults/kata-containers"

// dropInName is the drop-in pull-and-configure.sh writes into the single shim
// c8s configures on a node. kata-static ships every shim's TOML and both
// AMDSEV.fd and OVMF.inteltdx.fd on every node, and every OVMF build in that
// directory carries an ASEV metadata table — so neither the config set nor the
// firmware identifies the node's TEE. This file does.
const dropInName = "50-c8s.toml"

// kvmTDXParam reports whether the host kernel brought up the TDX module. It is
// the pre-install signal, before any c8s drop-in exists. Overridden in tests.
var kvmTDXParam = "/sys/module/kvm_intel/parameters/tdx"

// shimPlatform maps kata shim names to c8s's --hardware-platform vocabulary
// (c8s.kataShimName in internal/helmchart/c8s/templates/_helpers.tpl).
var shimPlatform = map[string]string{
	"qemu-snp":            platformSNP,
	"qemu-nvidia-gpu-snp": platformSNP,
	"qemu-tdx":            "Intel TDX",
	"qemu-nvidia-gpu-tdx": "Intel TDX",
}

const platformSNP = "AMD SEV-SNP"

// nonSNP is evidence that this node's TEE is not the one LaunchDigest models.
type nonSNP struct{ platform, evidence string }

// checkSNPPlatform refuses to measure on a node whose TEE is not SEV-SNP.
// Without it, `c8s kata measure` on a TDX node reads the AMDSEV.fd kata-static
// ships there anyway and prints a well-formed digest no guest will ever report.
// An empty kataConfigDir skips the check outright, for measuring an SNP fleet
// from a machine that is not one of its nodes.
func checkSNPPlatform(kataConfigDir string) error {
	if kataConfigDir == "" {
		return nil
	}
	e := detectNonSNP(kataConfigDir)
	if e == nil {
		return nil
	}
	return fmt.Errorf("this node runs %s (%s); c8s kata measure computes %s launch digests only. "+
		"TDX is not supported yet: it pins MRTD, which the TDX module builds over TDVF, not an SNP "+
		"launch digest. See docs/kata-launch-measurement.md",
		e.platform, e.evidence, platformSNP)
}

func detectNonSNP(kataConfigDir string) *nonSNP {
	if e := configuredShimPlatform(kataConfigDir); e != nil {
		return e
	}
	if b, err := os.ReadFile(kvmTDXParam); err == nil && strings.HasPrefix(strings.TrimSpace(string(b)), "Y") {
		return &nonSNP{platform: "Intel TDX", evidence: kvmTDXParam + "=Y"}
	}
	return nil
}

// configuredShimPlatform finds the shims carrying the c8s drop-in and reports
// the first whose platform is not SEV-SNP. Nothing configured means no
// evidence either way: the guest artifacts may have been fetched by hand for an
// off-node measurement.
func configuredShimPlatform(kataConfigDir string) *nonSNP {
	runtimes := filepath.Join(kataConfigDir, "runtimes")
	entries, err := os.ReadDir(runtimes)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		dropIn := filepath.Join(runtimes, e.Name(), "config.d", dropInName)
		if _, err := os.Stat(dropIn); err != nil {
			continue
		}
		p, known := shimPlatform[e.Name()]
		if !known {
			return &nonSNP{platform: fmt.Sprintf("the unrecognised kata shim %q", e.Name()), evidence: dropIn}
		}
		if p != platformSNP {
			return &nonSNP{platform: p, evidence: "kata shim " + e.Name() + ", " + dropIn}
		}
	}
	return nil
}
