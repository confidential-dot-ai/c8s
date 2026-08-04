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
// OVMF parsing, the digest accumulator and the VMSA pages come from
// github.com/virtee/sev-snp-measure-go. What this package adds is the sev_hashes
// page QEMU's kernel-hashes=on contributes, which that library has no entry
// point for. See docs/kata-launch-measurement.md.
package snpmeasure

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/virtee/sev-snp-measure-go/gctx"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"github.com/virtee/sev-snp-measure-go/vmsa"
)

// PageSize is the guest page granularity the launch digest is computed over.
const PageSize = gctx.PAGE_SIZE

// Config is the complete set of inputs to a SEV-SNP launch measurement.
type Config struct {
	// FirmwarePath is the OVMF image the VMM maps below 4 GiB (qemu -bios).
	FirmwarePath string

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
	fw, err := openFirmware(cfg.FirmwarePath)
	if err != nil {
		return nil, err
	}

	ld := gctx.New(nil)
	if err := ld.UpdateNormalPages(uint64(fw.GPA()), fw.Data()); err != nil {
		return nil, fmt.Errorf("measure firmware: %w", err)
	}
	if err := measureMetadata(ld, fw, cfg.KernelHashes); err != nil {
		return nil, err
	}

	resetEIP, err := fw.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("OVMF SEV-ES reset block: %w", err)
	}
	pages, err := vmsaPages(resetEIP, cfg)
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		if err := ld.UpdateVmsaPage(p); err != nil {
			return nil, fmt.Errorf("measure VMSA page: %w", err)
		}
	}
	return ld.LD(), nil
}

// FirmwareDigest returns the launch digest after only the OVMF image has been
// measured. It is the expensive, guest-independent prefix of LaunchDigest:
// callers measuring many pod shapes against one firmware can compute it once.
func FirmwareDigest(firmwarePath string) ([]byte, error) {
	fw, err := openFirmware(firmwarePath)
	if err != nil {
		return nil, err
	}
	ld := gctx.New(nil)
	if err := ld.UpdateNormalPages(uint64(fw.GPA()), fw.Data()); err != nil {
		return nil, fmt.Errorf("measure firmware: %w", err)
	}
	return ld.LD(), nil
}

// openFirmware parses an OVMF image, applying the bounds and metadata checks
// upstream's parser skips. See docs/pitfalls.md.
func openFirmware(path string) (fw *ovmf.OVMF, err error) {
	if path == "" {
		return nil, errors.New("firmware path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read firmware: %w", err)
	}
	if info.Size() == 0 || info.Size()%PageSize != 0 {
		return nil, fmt.Errorf("firmware size %d is not a positive multiple of %d", info.Size(), PageSize)
	}
	defer func() {
		if r := recover(); r != nil {
			fw, err = nil, fmt.Errorf("malformed OVMF image %s: %v", path, r)
		}
	}()

	img, err := ovmf.New(path)
	if err != nil {
		return nil, fmt.Errorf("parse firmware: %w", err)
	}
	// Upstream returns no error for an image without an ASEV table; measuring
	// one anyway yields a well-formed digest that matches nothing.
	if len(img.MetadataItems()) == 0 {
		return nil, errors.New("OVMF image has no SEV metadata sections")
	}
	return &img, nil
}

// measureMetadata walks OVMF's SEV metadata sections in file order, which is the
// order the VMM populates them in. It is upstream's guest.snpUpdateMetadataPages
// plus the SNP_KERNEL_HASHES case, which upstream rejects.
func measureMetadata(ld *gctx.GCTX, fw *ovmf.OVMF, kh *KernelHashes) error {
	sawKernelHashes := false
	for _, s := range fw.MetadataItems() {
		st, err := s.SectionType()
		if err != nil {
			return err
		}
		gpa := uint64(s.GPA)
		switch st {
		case ovmf.SNPSECMEM, ovmf.SVSM_CAA:
			if err := ld.UpdateZeroPages(gpa, int(s.Size)); err != nil {
				return fmt.Errorf("section at %#x size %d: %w", gpa, s.Size, err)
			}
		case ovmf.SNPSecrets:
			if err := ld.UpdateSecretsPage(gpa); err != nil {
				return err
			}
		case ovmf.CPUID:
			if err := ld.UpdateCpuidPage(gpa); err != nil {
				return err
			}
		case ovmf.SNPKernelHashes:
			sawKernelHashes = true
			if kh == nil {
				if err := ld.UpdateZeroPages(gpa, int(s.Size)); err != nil {
					return fmt.Errorf("section at %#x size %d: %w", gpa, s.Size, err)
				}
				continue
			}
			if s.Size != PageSize {
				return fmt.Errorf("kernel-hashes section is %d bytes, want %d", s.Size, PageSize)
			}
			off, err := hashTableOffset(fw)
			if err != nil {
				return err
			}
			if err := ld.UpdateNormalPages(gpa, kh.page(off)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unhandled OVMF metadata section type %d", st)
		}
	}
	if kh != nil && !sawKernelHashes {
		return errors.New("kernel hashes requested but OVMF has no SNP_KERNEL_HASHES metadata section")
	}
	return nil
}

// hashTableOffset is where inside its page OVMF expects QEMU's hash table. Only
// the offset reaches the measurement; the page comes from the metadata section.
// Without SEV_HASH_TABLE_RV the offset is unknown, and 0 would be a
// plausible-looking wrong answer.
func hashTableOffset(fw *ovmf.OVMF) (uint64, error) {
	errNoRV := errors.New("OVMF has no SEV_HASH_TABLE_RV entry to place the kernel hashes table")
	item, err := fw.TableItem(ovmf.SEV_HASH_TABLE_RV_GUID)
	if err != nil || len(item) < 4 {
		return 0, errNoRV
	}
	tableGPA := binary.LittleEndian.Uint32(item[:4])
	if tableGPA == 0 {
		return 0, errNoRV
	}
	return uint64(tableGPA) % PageSize, nil
}

// vmsaPages builds one VMSA page per vCPU: the BSP starts at the architectural
// reset vector, the APs at OVMF's SEV-ES reset block.
func vmsaPages(resetEIP uint32, cfg Config) ([][]byte, error) {
	v, err := vmsa.New(resetEIP, cfg.GuestFeatures, uint64(cfg.VCPUSig), vmmtypes.QEMU)
	if err != nil {
		return nil, fmt.Errorf("build VMSA: %w", err)
	}
	pages, err := v.Pages(cfg.VCPUs)
	if err != nil {
		return nil, fmt.Errorf("serialise VMSA: %w", err)
	}
	return pages, nil
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
