// Package snpmeasure computes the SEV-SNP launch measurement (launch digest) of
// a QEMU guest offline, from the firmware and boot artifacts, before the guest
// is ever started.
//
// The digest is an iterative SHA-384 over the PAGE_INFO structure of every page
// the AMD-SP measures at launch, in the order the VMM presents them: the OVMF
// image, the pages named by OVMF's SEV metadata table (zero / secrets / cpuid /
// kernel-hashes), then one VMSA page per vCPU. Because the VMSA pages carry the
// vCPU signature and are measured once per vCPU, and because kata puts
// "nr_cpus=N" in the measured kernel command line, guests that differ only in
// vCPU count have different launch digests.
//
// Algorithm and page layout follow AMD SEV-SNP ABI §8.17.2 (Table 67, PAGE_INFO)
// and the reference implementation at https://github.com/virtee/sev-snp-measure.
// virtee/sev-snp-measure-go is not a substitute: its README scopes it to "only
// measures the initial firmware", i.e. the firmware-only prefix FirmwareDigest
// computes, not the kernel-hashes page or the per-vCPU VMSA pages.
// See docs/kata-launch-measurement.md.
package snpmeasure

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
)

// PageSize is the guest page granularity the launch digest is computed over.
const PageSize = 4096

// Config is the complete set of inputs to a SEV-SNP launch measurement.
type Config struct {
	// Firmware is the raw OVMF image the VMM maps below 4 GiB (qemu -bios).
	Firmware []byte

	// KernelHashes, when non-nil, measures QEMU's kernel/initrd/cmdline hash
	// table into the digest. Set it iff the guest boots with
	// -object sev-snp-guest,...,kernel-hashes=on.
	KernelHashes *KernelHashes

	// VCPUs is the number of vCPUs the guest launches with (qemu -smp N).
	VCPUs int

	// VCPUSig is the CPUID Fn0000_0001_EAX signature of the guest vCPU model,
	// loaded into RDX of every VMSA. See VCPUSignature.
	VCPUSig uint32

	// GuestFeatures is the VMSA SEV_FEATURES field (0x1 = SNPActive).
	GuestFeatures uint64
}

// LaunchDigest returns the 48-byte SEV-SNP launch measurement for cfg.
func LaunchDigest(cfg Config) ([]byte, error) {
	if cfg.VCPUs < 1 {
		return nil, fmt.Errorf("vcpus must be >= 1, got %d", cfg.VCPUs)
	}
	if len(cfg.Firmware)%PageSize != 0 {
		return nil, fmt.Errorf("firmware size %d is not a multiple of %d", len(cfg.Firmware), PageSize)
	}
	fw, err := ParseFirmware(cfg.Firmware)
	if err != nil {
		return nil, err
	}

	ld := newDigest()
	ld.normalPages(fw.GPA, cfg.Firmware)

	if err := measureMetadata(ld, fw, cfg.KernelHashes); err != nil {
		return nil, err
	}

	bsp := vmsaPage(bspResetEIP, cfg.GuestFeatures, cfg.VCPUSig)
	ap := vmsaPage(fw.ResetEIP, cfg.GuestFeatures, cfg.VCPUSig)
	for i := range cfg.VCPUs {
		if i == 0 {
			ld.vmsaPage(bsp)
		} else {
			ld.vmsaPage(ap)
		}
	}
	return ld.value(), nil
}

// FirmwareDigest returns the launch digest after only the OVMF image has been
// measured. It is the expensive, guest-independent prefix of LaunchDigest:
// callers measuring many pod shapes against one firmware can compute it once.
func FirmwareDigest(firmware []byte) ([]byte, error) {
	if len(firmware)%PageSize != 0 {
		return nil, fmt.Errorf("firmware size %d is not a multiple of %d", len(firmware), PageSize)
	}
	fw, err := ParseFirmware(firmware)
	if err != nil {
		return nil, err
	}
	ld := newDigest()
	ld.normalPages(fw.GPA, firmware)
	return ld.value(), nil
}

// measureMetadata walks OVMF's SEV metadata sections in file order, which is the
// order the VMM populates them in.
func measureMetadata(ld *digest, fw *Firmware, kh *KernelHashes) error {
	sawKernelHashes := false
	for _, s := range fw.Sections {
		switch s.Type {
		case SectionSecMem:
			if err := ld.zeroPages(s.GPA, s.Size); err != nil {
				return err
			}
		case SectionSecrets:
			ld.singlePage(pageTypeSecrets, s.GPA)
		case SectionCPUID:
			ld.singlePage(pageTypeCPUID, s.GPA)
		case SectionSVSMCAA:
			if err := ld.zeroPages(s.GPA, s.Size); err != nil {
				return err
			}
		case SectionKernelHashes:
			sawKernelHashes = true
			if kh == nil {
				if err := ld.zeroPages(s.GPA, s.Size); err != nil {
					return err
				}
				continue
			}
			if s.Size != PageSize {
				return fmt.Errorf("kernel-hashes section is %d bytes, want %d", s.Size, PageSize)
			}
			// Without SEV_HASH_TABLE_RV the table's offset in the page is
			// unknown, and offset 0 would be a plausible-looking wrong answer.
			if fw.HashTableGPA == 0 {
				return errors.New("OVMF has no SEV_HASH_TABLE_RV entry to place the kernel hashes table")
			}
			ld.normalPages(s.GPA, kh.page(fw.HashTableGPA%PageSize))
		default:
			return fmt.Errorf("unknown OVMF metadata section type %d", s.Type)
		}
	}
	if kh != nil && !sawKernelHashes {
		return errors.New("kernel hashes requested but OVMF has no SNP_KERNEL_HASHES metadata section")
	}
	return nil
}

// KernelHashes holds the SHA-256 digests QEMU publishes to OVMF when
// kernel-hashes=on, so the firmware can refuse a kernel the host swapped out.
type KernelHashes struct {
	Kernel  [sha256.Size]byte
	Initrd  [sha256.Size]byte
	Cmdline [sha256.Size]byte
}

// NewKernelHashes hashes the boot artifacts the way QEMU does in
// sev_add_kernel_loader_hashes(): the whole kernel file (QEMU skips its usual
// setup-header patching under SEV so the hash matches the file on disk), the
// initrd (the empty string when there is none), and the command line with a
// trailing NUL.
func NewKernelHashes(kernel, initrd []byte, cmdline string) KernelHashes {
	return KernelHashes{
		Kernel:  sha256.Sum256(kernel),
		Initrd:  sha256.Sum256(initrd),
		Cmdline: sha256.Sum256(append([]byte(cmdline), 0)),
	}
}

// KernelHashesFromFiles is NewKernelHashes over files, streaming rather than
// loading multi-MiB artifacts. An empty initrdPath means "no initrd".
func KernelHashesFromFiles(kernelPath, initrdPath, cmdline string) (*KernelHashes, error) {
	kh := KernelHashes{Cmdline: sha256.Sum256(append([]byte(cmdline), 0))}
	var err error
	if kh.Kernel, err = sha256File(kernelPath); err != nil {
		return nil, err
	}
	kh.Initrd = sha256.Sum256(nil)
	if initrdPath != "" {
		if kh.Initrd, err = sha256File(initrdPath); err != nil {
			return nil, err
		}
	}
	return &kh, nil
}

func sha256File(path string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, fmt.Errorf("read %s: %w", path, err)
	}
	return [sha256.Size]byte(h.Sum(nil)), nil
}

// digest is the running launch measurement.
type digest struct{ ld [sha512.Size384]byte }

const (
	pageTypeNormal  = 0x01
	pageTypeVMSA    = 0x02
	pageTypeZero    = 0x03
	pageTypeSecrets = 0x05
	pageTypeCPUID   = 0x06

	// pageInfoSize is the PAGE_INFO length the AMD-SP hashes (ABI Table 67).
	pageInfoSize = 0x70

	// vmsaGPA is the fixed GPA the RMP records for every VMSA page.
	vmsaGPA = 0xFFFFFFFFF000

	// bspResetEIP is the x86 architectural reset vector, used for vCPU 0. APs
	// start at the EIP in OVMF's SEV-ES reset block instead.
	bspResetEIP = 0xFFFFFFF0
)

func newDigest() *digest { return &digest{} }

func (d *digest) value() []byte { return d.ld[:] }

// update folds one measured page into the digest.
func (d *digest) update(pageType byte, gpa uint64, contents [sha512.Size384]byte) {
	var pi [pageInfoSize]byte
	copy(pi[0:48], d.ld[:])
	copy(pi[48:96], contents[:])
	pi[0x60] = byte(pageInfoSize) // LENGTH, u16 LE
	pi[0x62] = pageType
	// 0x63 IMI_PAGE, 0x64-0x66 VMPL{3,2,1}_PERMS, 0x67 reserved: all zero.
	putU64(pi[0x68:], gpa)
	d.ld = sha512.Sum384(pi[:])
}

func (d *digest) normalPages(startGPA uint64, data []byte) {
	for off := 0; off < len(data); off += PageSize {
		d.update(pageTypeNormal, startGPA+uint64(off), sha512.Sum384(data[off:off+PageSize]))
	}
}

func (d *digest) vmsaPage(page []byte) {
	d.update(pageTypeVMSA, vmsaGPA, sha512.Sum384(page))
}

// zeroPages measures a span as unencrypted-but-zeroed. CONTENTS is 48 zero
// bytes, not the hash of a zero page.
func (d *digest) zeroPages(gpa uint64, length uint32) error {
	if length%PageSize != 0 {
		return fmt.Errorf("section at %#x has size %d, not a multiple of %d", gpa, length, PageSize)
	}
	var zero [sha512.Size384]byte
	for off := uint32(0); off < length; off += PageSize {
		d.update(pageTypeZero, gpa+uint64(off), zero)
	}
	return nil
}

func (d *digest) singlePage(pageType byte, gpa uint64) {
	var zero [sha512.Size384]byte
	d.update(pageType, gpa, zero)
}

func putU16(b []byte, v uint16) { b[0] = byte(v); b[1] = byte(v >> 8) }

func putU32(b []byte, v uint32) {
	for i := range 4 {
		b[i] = byte(v >> (8 * i))
	}
}

func putU64(b []byte, v uint64) {
	for i := range 8 {
		b[i] = byte(v >> (8 * i))
	}
}
