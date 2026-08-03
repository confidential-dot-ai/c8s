package snpmeasure

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Byte offsets into the SEV-ES save area (AMD APM Vol 2 Table B-4, field names
// from struct sev_es_save_area in Linux arch/x86/include/asm/svm.h). Only the
// fields QEMU/KVM set to a non-zero reset value are listed; the rest of the
// 4 KiB page is zero.
const (
	offES     = 0x000
	offCS     = 0x010
	offSS     = 0x020
	offDS     = 0x030
	offFS     = 0x040
	offGS     = 0x050
	offGDTR   = 0x060
	offLDTR   = 0x070
	offIDTR   = 0x080
	offTR     = 0x090
	offEFER   = 0x0D0
	offCR4    = 0x148
	offCR0    = 0x158
	offDR7    = 0x160
	offDR6    = 0x168
	offRFLAGS = 0x170
	offRIP    = 0x178
	offGPAT   = 0x268
	offRDX    = 0x310
	offSEVFt  = 0x3B0
	offXCR0   = 0x3E8
	offMXCSR  = 0x408
	offX87FCW = 0x410
)

// vmsaPage builds the 4 KiB VMSA the VMM hands the AMD-SP for one vCPU.
// eip selects the entry point: the reset vector for the BSP, OVMF's SEV-ES
// reset block for every AP. Values match QEMU's reset state; a different VMM
// (EC2, GCE) would produce a different page and a different digest.
func vmsaPage(eip, sevFeatures uint64, vcpuSig uint32) []byte {
	p := make([]byte, PageSize)
	seg := func(off int, selector, attrib uint16, limit uint32, base uint64) {
		putU16(p[off:], selector)
		putU16(p[off+2:], attrib)
		putU32(p[off+4:], limit)
		putU64(p[off+8:], base)
	}
	seg(offES, 0, 0x93, 0xFFFF, 0)
	seg(offCS, 0xF000, 0x9B, 0xFFFF, eip&0xFFFF0000)
	seg(offSS, 0, 0x93, 0xFFFF, 0)
	seg(offDS, 0, 0x93, 0xFFFF, 0)
	seg(offFS, 0, 0x93, 0xFFFF, 0)
	seg(offGS, 0, 0x93, 0xFFFF, 0)
	seg(offGDTR, 0, 0, 0xFFFF, 0)
	seg(offLDTR, 0, 0x82, 0xFFFF, 0)
	seg(offIDTR, 0, 0, 0xFFFF, 0)
	seg(offTR, 0, 0x8B, 0xFFFF, 0)

	putU64(p[offEFER:], 0x1000) // KVM sets EFER_SVME
	putU64(p[offCR4:], 0x40)    // KVM sets X86_CR4_MCE
	putU64(p[offCR0:], 0x10)
	putU64(p[offDR7:], 0x400)
	putU64(p[offDR6:], 0xFFFF0FF0)
	putU64(p[offRFLAGS:], 0x2)
	putU64(p[offRIP:], eip&0xFFFF)
	putU64(p[offGPAT:], 0x0007_0406_0007_0406) // PAT MSR reset value, APM Vol 2 §A.3
	putU64(p[offRDX:], uint64(vcpuSig))
	putU64(p[offSEVFt:], sevFeatures)
	putU64(p[offXCR0:], 0x1)
	putU32(p[offMXCSR:], 0x1F80)
	putU16(p[offX87FCW:], 0x37F)
	return p
}

// VCPUSignature returns the CPUID Fn0000_0001_EAX signature for a family /
// model / stepping triple (AMD CPUID Specification, publication 25481).
func VCPUSignature(family, model, stepping uint32) uint32 {
	familyLow, familyHigh := family, uint32(0)
	if family > 0xF {
		familyLow, familyHigh = 0xF, (family-0xF)&0xFF
	}
	return familyHigh<<20 | (model>>4&0xF)<<16 | familyLow<<8 | (model&0xF)<<4 | stepping&0xF
}

// vcpuTypes mirrors the QEMU -cpu models kata may launch a guest with. The
// signature lands in RDX of every VMSA, so picking the wrong one silently
// changes the digest.
var vcpuTypes = map[string]uint32{
	"EPYC":          VCPUSignature(23, 1, 2),
	"EPYC-v1":       VCPUSignature(23, 1, 2),
	"EPYC-v2":       VCPUSignature(23, 1, 2),
	"EPYC-IBPB":     VCPUSignature(23, 1, 2),
	"EPYC-v3":       VCPUSignature(23, 1, 2),
	"EPYC-v4":       VCPUSignature(23, 1, 2),
	"EPYC-Rome":     VCPUSignature(23, 49, 0),
	"EPYC-Rome-v1":  VCPUSignature(23, 49, 0),
	"EPYC-Rome-v2":  VCPUSignature(23, 49, 0),
	"EPYC-Rome-v3":  VCPUSignature(23, 49, 0),
	"EPYC-Milan":    VCPUSignature(25, 1, 1),
	"EPYC-Milan-v1": VCPUSignature(25, 1, 1),
	"EPYC-Milan-v2": VCPUSignature(25, 1, 1),
	"EPYC-Genoa":    VCPUSignature(25, 17, 0),
	"EPYC-Genoa-v1": VCPUSignature(25, 17, 0),
	"EPYC-Turin":    VCPUSignature(26, 0, 0),
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
