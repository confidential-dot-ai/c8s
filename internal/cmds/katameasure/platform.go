package katameasure

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultKataConfigDir is kata-deploy's config root: one runtimes/<shim>/
// directory per hypervisor shim, each with its own config.d.
const DefaultKataConfigDir = "/opt/kata/share/defaults/kata-containers"

// dropInName is the drop-in pull-and-configure.sh writes into the shims c8s
// configures on a node. kata-static ships every shim's TOML and both AMDSEV.fd
// and OVMF.inteltdx.fd on every node, so neither the config set nor the
// firmware identifies the node's TEE. This file does.
const dropInName = "50-c8s.toml"

// kvmTDXParam is the pre-install signal, before any drop-in exists. Overridden
// in tests.
var kvmTDXParam = "/sys/module/kvm_intel/parameters/tdx"

// shimPlatform maps the kata shims c8s configures (c8s.kataShimName in
// internal/helmchart/c8s/templates/_helpers.tpl) to --platform values.
var shimPlatform = map[string]string{
	"qemu-snp":            platformSNP,
	"qemu-nvidia-gpu-snp": platformSNP,
	"qemu-tdx":            platformTDX,
	"qemu-nvidia-gpu-tdx": platformTDX,
}

// detectPlatform reports this node's TEE in --platform vocabulary, with the
// evidence that decided it. Both are empty when the node says nothing: an empty
// kataConfigDir, no c8s drop-in and no TDX module.
func detectPlatform(kataConfigDir string) (platform, evidence string) {
	if kataConfigDir == "" {
		return "", ""
	}
	if p, ev := configuredShimPlatform(kataConfigDir); p != "" {
		return p, ev
	}
	if b, err := os.ReadFile(kvmTDXParam); err == nil && strings.HasPrefix(strings.TrimSpace(string(b)), "Y") {
		return platformTDX, kvmTDXParam + "=Y"
	}
	return "", ""
}

// configuredShimPlatform reports the platform of the shims carrying the c8s
// drop-in — the config that will actually boot this guest. A node normally
// configures one platform's shims (the SNP node also configures
// qemu-nvidia-gpu-snp); TDX wins a mixed set, because measuring a TDX node as
// SNP is the silent failure this detection exists to stop.
func configuredShimPlatform(kataConfigDir string) (platform, evidence string) {
	runtimes := filepath.Join(kataConfigDir, "runtimes")
	entries, err := os.ReadDir(runtimes)
	if err != nil {
		return "", ""
	}
	for _, e := range entries {
		dropIn := filepath.Join(runtimes, e.Name(), "config.d", dropInName)
		if _, err := os.Stat(dropIn); err != nil {
			continue
		}
		p, known := shimPlatform[e.Name()]
		if !known {
			continue
		}
		if platform == "" || (platform != platformTDX && p == platformTDX) {
			platform, evidence = p, "kata shim "+e.Name()+", "+dropIn
		}
	}
	return platform, evidence
}
