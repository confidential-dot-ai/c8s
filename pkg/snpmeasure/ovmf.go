package snpmeasure

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SectionType identifies an OVMF SEV metadata section (edk2
// OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm).
type SectionType uint32

const (
	SectionSecMem       SectionType = 1
	SectionSecrets      SectionType = 2
	SectionCPUID        SectionType = 3
	SectionSVSMCAA      SectionType = 4
	SectionKernelHashes SectionType = 0x10
)

// Section is one entry of OVMF's SEV metadata table.
type Section struct {
	GPA  uint64
	Size uint32
	Type SectionType
}

// Firmware is the parsed view of an OVMF image needed to measure it.
type Firmware struct {
	// GPA is where the VMM maps the image: it ends at 4 GiB.
	GPA uint64
	// ResetEIP is the AP start address from OVMF's SEV-ES reset block.
	ResetEIP uint64
	// HashTableGPA is where OVMF expects QEMU's kernel-hashes table. Only its
	// offset within the page matters to the measurement; the page itself is
	// named by the SNP_KERNEL_HASHES metadata section.
	HashTableGPA uint64
	Sections     []Section
}

// GUIDs of the entries c8s reads out of OVMF's footer table.
var (
	guidTableFooter  = mustGUID("96b582de-1fb2-45f7-baea-a366c55a082d")
	guidSEVMetadata  = mustGUID("dc886566-984a-4798-a75e-5585a7bf67cc")
	guidResetBlock   = mustGUID("00f771de-1a7e-4fcb-890e-68c77e2fb44e")
	guidHashTableRV  = mustGUID("7255371f-3a3b-4b04-927b-1da6efa8d454")
	errNoFooterTable = errors.New("OVMF image has no GUID footer table")
)

const (
	// fourGiB is where the VMM places the end of the firmware image.
	fourGiB = 0x100000000
	// tableEntrySize is sizeof(struct { uint16 size; uint8 guid[16]; }).
	tableEntrySize = 18
	// footerTableSkip is the padding between the footer entry and EOF.
	footerTableSkip = 32
)

// ParseFirmware reads the GUID footer table and SEV metadata out of an OVMF
// image. The table is stored backwards from a fixed offset near the end of the
// image, so it is walked from the last entry to the first.
func ParseFirmware(data []byte) (*Firmware, error) {
	table, err := parseFooterTable(data)
	if err != nil {
		return nil, err
	}
	fw := &Firmware{GPA: fourGiB - uint64(len(data))}

	if e, ok := table[guidResetBlock]; ok && len(e) >= 4 {
		fw.ResetEIP = uint64(u32(e))
	}
	if e, ok := table[guidHashTableRV]; ok && len(e) >= 4 {
		fw.HashTableGPA = uint64(u32(e))
	}
	meta, ok := table[guidSEVMetadata]
	if !ok || len(meta) < 4 {
		return nil, errors.New("OVMF image has no SEV metadata entry")
	}
	if fw.Sections, err = parseSEVMetadata(data, u32(meta)); err != nil {
		return nil, err
	}
	return fw, nil
}

func parseFooterTable(data []byte) (map[[16]byte][]byte, error) {
	if len(data) < footerTableSkip+tableEntrySize {
		return nil, errNoFooterTable
	}
	footerAt := len(data) - footerTableSkip - tableEntrySize
	size := int(u16(data[footerAt:]))
	if [16]byte(data[footerAt+2:footerAt+18]) != guidTableFooter || size < tableEntrySize {
		return nil, errNoFooterTable
	}
	body := size - tableEntrySize
	if body < 0 || footerAt-body < 0 {
		return nil, fmt.Errorf("OVMF footer table size %d overruns the image", size)
	}
	rest := data[footerAt-body : footerAt]

	table := make(map[[16]byte][]byte)
	for len(rest) >= tableEntrySize {
		hdr := rest[len(rest)-tableEntrySize:]
		entrySize := int(u16(hdr))
		if entrySize < tableEntrySize || entrySize > len(rest) {
			return nil, fmt.Errorf("invalid OVMF table entry size %d", entrySize)
		}
		table[[16]byte(hdr[2:18])] = rest[len(rest)-entrySize : len(rest)-tableEntrySize]
		rest = rest[:len(rest)-entrySize]
	}
	return table, nil
}

// parseSEVMetadata reads the ASEV header and its section descriptors, located
// offsetFromEnd bytes back from the end of the image.
func parseSEVMetadata(data []byte, offsetFromEnd uint32) ([]Section, error) {
	if int(offsetFromEnd) > len(data) {
		return nil, fmt.Errorf("SEV metadata offset %d overruns the image", offsetFromEnd)
	}
	m := data[len(data)-int(offsetFromEnd):]
	const headerSize = 16
	if len(m) < headerSize {
		return nil, errors.New("truncated SEV metadata header")
	}
	if string(m[0:4]) != "ASEV" {
		return nil, fmt.Errorf("bad SEV metadata signature %q", m[0:4])
	}
	if v := u32(m[8:]); v != 1 {
		return nil, fmt.Errorf("unsupported SEV metadata version %d", v)
	}
	n := int(u32(m[12:]))
	const descSize = 12
	if headerSize+n*descSize > len(m) {
		return nil, errors.New("truncated SEV metadata section table")
	}
	out := make([]Section, n)
	for i := range out {
		d := m[headerSize+i*descSize:]
		out[i] = Section{GPA: uint64(u32(d)), Size: u32(d[4:]), Type: SectionType(u32(d[8:]))}
	}
	return out, nil
}

func u16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// mustGUID converts a canonical GUID string to the mixed-endian byte order UEFI
// stores it in: the first three fields little-endian, the last two big-endian.
func mustGUID(s string) [16]byte {
	f := strings.Split(s, "-")
	if len(f) != 5 {
		panic("snpmeasure: malformed GUID " + s)
	}
	b, err := hex.DecodeString(strings.Join(f, ""))
	if err != nil || len(b) != 16 {
		panic("snpmeasure: malformed GUID " + s)
	}
	var g [16]byte
	copy(g[:], b)
	putU32(g[0:4], be32(b[0:4]))
	putU16(g[4:6], be16(b[4:6]))
	putU16(g[6:8], be16(b[6:8]))
	return g
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
