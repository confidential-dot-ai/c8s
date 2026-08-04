package snpmeasure

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/virtee/sev-snp-measure-go/cpuid"
)

// VCPUSignature returns the CPUID Fn0000_0001_EAX signature for a family /
// model / stepping triple (AMD CPUID Specification, publication 25481).
func VCPUSignature(family, model, stepping uint32) uint32 {
	familyLow, familyHigh := family, uint32(0)
	if family > 0xF {
		familyLow, familyHigh = 0xF, (family-0xF)&0xFF
	}
	return familyHigh<<20 | (model>>4&0xF)<<16 | familyLow<<8 | (model&0xF)<<4 | stepping&0xF
}

// vcpuTypes maps the QEMU -cpu models kata may launch a guest with to the
// signature that lands in RDX of every VMSA, so picking the wrong one silently
// changes the digest. Upstream's table, plus EPYC-Turin, which it lacks.
var vcpuTypes = knownVCPUTypes()

func knownVCPUTypes() map[string]uint32 {
	m := map[string]uint32{"EPYC-Turin": VCPUSignature(26, 0, 0)}
	for name, sig := range cpuid.CpuSigs {
		m[name] = uint32(sig)
	}
	return m
}

// VCPUSignatureByName resolves a QEMU -cpu model name to its signature.
func VCPUSignatureByName(name string) (uint32, error) {
	sig, ok := vcpuTypes[name]
	if !ok {
		return 0, fmt.Errorf("unknown vcpu type %q (known: %s)", name, strings.Join(VCPUTypes(), ", "))
	}
	return sig, nil
}

// VCPUTypes lists the known QEMU -cpu model names, sorted.
func VCPUTypes() []string {
	return slices.Sorted(maps.Keys(vcpuTypes))
}
