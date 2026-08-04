package snpmeasure

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/virtee/sev-snp-measure-go/ovmf"
)

// testdata/ovmf_AmdSev_suffix.bin is the 4 KiB OVMF suffix fixture from
// virtee/sev-snp-measure (Apache-2.0), tests/fixtures/. The expected digests
// below are that project's own committed test vectors, so they validate this
// implementation against an independent one without a multi-GB guest image.
const fixture = "testdata/ovmf_AmdSev_suffix.bin"

// writeFirmware puts b in a temp file, for the cases that measure a mutated or
// truncated image.
func writeFirmware(t *testing.T, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ovmf.fd")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestFirmwareDigest(t *testing.T) {
	got, err := FirmwareDigest(fixture)
	if err != nil {
		t.Fatal(err)
	}
	const want = "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74"
	if hex.EncodeToString(got) != want {
		t.Errorf("firmware digest\n got %s\nwant %s", hex.EncodeToString(got), want)
	}
}

// TestParseFirmware pins what the upstream OVMF parser reads out of the
// fixture, so a dependency bump that changes any of it fails here rather than
// silently moving every digest.
func TestParseFirmware(t *testing.T) {
	fw, err := openFirmware(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if fw.GPA() != 0xFFFFF000 {
		t.Errorf("GPA = %#x, want 0xfffff000", fw.GPA())
	}
	resetEIP, err := fw.SevESResetEIP()
	if err != nil {
		t.Fatal(err)
	}
	if resetEIP != 0x80B004 {
		t.Errorf("ResetEIP = %#x, want 0x80b004", resetEIP)
	}
	// The hash table's page comes from the metadata section; only this value's
	// offset within the page reaches the measurement.
	off, err := hashTableOffset(fw)
	if err != nil {
		t.Fatal(err)
	}
	if off != 0xC00 {
		t.Errorf("hash table offset = %#x, want 0xc00 (from SEV_HASH_TABLE_RV 0x810c00)", off)
	}
	want := []ovmf.MetadataSection{
		{GPA: 0x800000, Size: 0x9000, SectionTypeInt: uint32(ovmf.SNPSECMEM)},
		{GPA: 0x80A000, Size: 0x3000, SectionTypeInt: uint32(ovmf.SNPSECMEM)},
		{GPA: 0x80D000, Size: 0x1000, SectionTypeInt: uint32(ovmf.SNPSecrets)},
		{GPA: 0x80E000, Size: 0x1000, SectionTypeInt: uint32(ovmf.CPUID)},
		{GPA: 0x80F000, Size: 0x1000, SectionTypeInt: uint32(ovmf.SVSM_CAA)},
		{GPA: 0x810000, Size: 0x1000, SectionTypeInt: uint32(ovmf.SNPKernelHashes)},
		{GPA: 0x811000, Size: 0xF000, SectionTypeInt: uint32(ovmf.SNPSECMEM)},
	}
	got := fw.MetadataItems()
	if len(got) != len(want) {
		t.Fatalf("got %d sections, want %d", len(got), len(want))
	}
	for i, s := range got {
		if s != want[i] {
			t.Errorf("section %d = %+v, want %+v", i, s, want[i])
		}
	}
}

// TestLaunchDigestVectors checks the full pipeline against sev-snp-measure's
// committed vectors. Those runs pass /dev/null for kernel and initrd, i.e. the
// hashes of empty content.
func TestLaunchDigestVectors(t *testing.T) {
	sig, err := VCPUSignatureByName("EPYC-v4")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		vcpus    int
		features uint64
		cmdline  string
		want     string
	}{
		{"1vcpu/snp+debugswap/empty-cmdline", 1, 0x21, "",
			"329c8ce0972ae52343b64d34a434a86f245dfd74f5ed7aae15d22efc78fb9683632b9b50e4e1d7fa41179ef98a7ef198"},
		{"1vcpu/snp/empty-cmdline", 1, 0x1, "",
			"ddc5224521617a536ee7ce9dd6224d1b58a8d4fda1c741f3ac99fc4bfa04ba6e9fc98646d4a07a9079397fa3852819b5"},
		{"1vcpu/snp+debugswap/cmdline", 1, 0x21, "console=ttyS0 loglevel=7",
			"803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba7e534442e7e1e17895dfe778d0228977"},
		{"1vcpu/snp/cmdline", 1, 0x1, "console=ttyS0 loglevel=7",
			"6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa"},
		{"4vcpu/snp/cmdline", 4, 0x1, "console=ttyS0 loglevel=7",
			"ef493c232fc8fac47f485398e3873a84ac5c45570bcd8a34aba093c084060534d633824df94b9eba33dc3a3052ae565a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kh := NewKernelHashes(nil, nil, tc.cmdline)
			ld, err := LaunchDigest(Config{
				FirmwarePath: fixture, KernelHashes: &kh, VCPUs: tc.vcpus,
				VCPUSig: sig, GuestFeatures: tc.features,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ld); got != tc.want {
				t.Errorf("\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestLaunchDigestVCPUsDiffer is the property that forces per-pod-shape
// measurement sets under --cvm-mode=pod.
func TestLaunchDigestVCPUsDiffer(t *testing.T) {
	sig, _ := VCPUSignatureByName("EPYC-v4")
	kh := NewKernelHashes(nil, nil, "x")
	digest := func(n int) string {
		ld, err := LaunchDigest(Config{FirmwarePath: fixture, KernelHashes: &kh, VCPUs: n, VCPUSig: sig, GuestFeatures: 1})
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(ld)
	}
	if digest(1) == digest(2) {
		t.Error("1 and 2 vCPUs produced the same launch digest")
	}
}

func TestLaunchDigestWithoutKernelHashes(t *testing.T) {
	sig, _ := VCPUSignatureByName("EPYC-v4")
	ld, err := LaunchDigest(Config{
		FirmwarePath: fixture, VCPUs: 1, VCPUSig: sig, GuestFeatures: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = "19358ba9a7615534a9a1e2f0dfc29384dcd4dcb7062ff9c6013b26869a5fc6ecabe033c48dd6f6db5d6d76e7c5df632d"
	if got := hex.EncodeToString(ld); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

func TestVCPUSignature(t *testing.T) {
	cases := map[string]uint32{
		"EPYC-v4":       0x800F12,
		"EPYC-Rome":     0x830F10,
		"EPYC-Milan":    0xA00F11,
		"EPYC-Genoa":    0xA10F10,
		"EPYC-Turin":    0xB00F00,
		"EPYC-Milan-v2": 0xA00F11,
	}
	for name, want := range cases {
		got, err := VCPUSignatureByName(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s = %#x, want %#x", name, got, want)
		}
	}
	if _, err := VCPUSignatureByName("EPYC-v99"); err == nil {
		t.Error("unknown vcpu type must fail")
	}
}

// TestKernelHashesQEMUQuirks pins the two conventions that silently change the
// digest if reimplemented naively: the command line is hashed with a trailing
// NUL, and a missing initrd still hashes as the empty string.
func TestKernelHashesQEMUQuirks(t *testing.T) {
	kh := NewKernelHashes(nil, nil, "")
	if got := hex.EncodeToString(kh.Cmdline[:]); got != hex.EncodeToString(sha256sumOf([]byte{0})) {
		t.Errorf("empty cmdline hash = %s, want sha256 of a single NUL", got)
	}
	if got := hex.EncodeToString(kh.Initrd[:]); got != hex.EncodeToString(sha256sumOf(nil)) {
		t.Errorf("absent initrd hash = %s, want sha256 of the empty string", got)
	}
	withCmdline := NewKernelHashes(nil, nil, "root=/dev/dm-0")
	if withCmdline.Cmdline != sha256.Sum256([]byte("root=/dev/dm-0\x00")) {
		t.Error("cmdline hash must cover the trailing NUL")
	}
}

// TestKernelHashesTable pins the wire layout: header GUID, the unpadded length
// in a padded buffer, and the cmdline/initrd/kernel entry order.
func TestKernelHashesTable(t *testing.T) {
	kh := NewKernelHashes([]byte("FAKEKERNEL"), []byte("FAKEINITRD"), "console=ttyS0 loglevel=7")
	tbl := kh.table()
	if len(tbl) != 176 {
		t.Fatalf("table is %d bytes, want 176", len(tbl))
	}
	if got := hex.EncodeToString(tbl[:16]); got != "06d63894224fc94cb479a793d411fd21" {
		t.Errorf("header GUID = %s", got)
	}
	if l := binary.LittleEndian.Uint16(tbl[16:]); l != 168 {
		t.Errorf("header length = %d, want 168 (unpadded)", l)
	}
	for i, want := range []struct {
		guid string
		hash [sha256.Size]byte
	}{
		{"d82dd09720bd944caa78e7714d36ab2a", kh.Cmdline},
		{"31f7ba442f3ad74b9af141e29169781d", kh.Initrd},
		{"3794e74dd2ab7f42b835d5b172d2045b", kh.Kernel},
	} {
		at := 18 + i*hashEntrySize
		if got := hex.EncodeToString(tbl[at : at+16]); got != want.guid {
			t.Errorf("entry %d GUID = %s, want %s", i, got, want.guid)
		}
		if l := binary.LittleEndian.Uint16(tbl[at+16:]); l != hashEntrySize {
			t.Errorf("entry %d length = %d, want %d", i, l, hashEntrySize)
		}
		if [sha256.Size]byte(tbl[at+18:at+18+sha256.Size]) != want.hash {
			t.Errorf("entry %d hash mismatch", i)
		}
	}
	for _, b := range tbl[168:] {
		if b != 0 {
			t.Error("padding must be zero")
			break
		}
	}
}

func TestKernelHashesFromFiles(t *testing.T) {
	const cmdline = "console=ttyS0 loglevel=7"
	dir := t.TempDir()
	kernel := dir + "/vmlinuz"
	initrd := dir + "/initrd.img"
	for path, content := range map[string]string{kernel: "FAKEKERNEL", initrd: "FAKEINITRD"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := KernelHashesFromFiles(kernel, "", cmdline)
	if err != nil {
		t.Fatal(err)
	}
	want := NewKernelHashes([]byte("FAKEKERNEL"), nil, cmdline)
	if *got != want {
		t.Error("KernelHashesFromFiles disagrees with NewKernelHashes")
	}
	got, err = KernelHashesFromFiles(kernel, initrd, cmdline)
	if err != nil {
		t.Fatal(err)
	}
	// An initrd that hashed as absent would measure the same as the no-initrd
	// guest, so a swapped initrd would pass an allowlist built without one.
	want = NewKernelHashes([]byte("FAKEKERNEL"), []byte("FAKEINITRD"), cmdline)
	if *got != want {
		t.Error("KernelHashesFromFiles ignored the initrd")
	}

	// An unreadable artifact must not hash as the empty string.
	unreadable := map[string][2]string{
		"missing kernel":        {dir + "/absent", ""},
		"missing initrd":        {kernel, dir + "/absent"},
		"kernel is a directory": {dir, ""},
		"initrd is a directory": {kernel, dir},
	}
	for name, paths := range unreadable {
		t.Run(name, func(t *testing.T) {
			kh, err := KernelHashesFromFiles(paths[0], paths[1], cmdline)
			if err == nil {
				t.Fatalf("want error, got %+v", kh)
			}
			if kh != nil {
				t.Errorf("hashes %+v returned alongside error %v", kh, err)
			}
		})
	}
}

// TestLaunchDigestRejectsBadInput is the fail-closed contract: malformed input
// must yield an error and no digest, never a well-formed 48 bytes that matches
// no guest — pinned into an allowlist, that rejects every pod with nothing to
// diagnose. Some cases panic upstream's unchecked indexing; that must surface
// as an error too. wantErr keeps the causes distinguishable.
func TestLaunchDigestRejectsBadInput(t *testing.T) {
	fw := readFixture(t)
	sig, _ := VCPUSignatureByName("EPYC-v4")
	kh := NewKernelHashes(nil, nil, "")
	plain := func(path string) Config {
		return Config{FirmwarePath: path, VCPUs: 1, VCPUSig: sig, GuestFeatures: 1}
	}
	hashed := func(path string) Config {
		c := plain(path)
		c.KernelHashes = &kh
		return c
	}
	patched := func(st ovmf.SectionType, edit func(*ovmf.MetadataSection)) string {
		return writeFirmware(t, patchMetadataSection(t, fw, st, edit))
	}

	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"zero vcpus", Config{FirmwarePath: fixture, VCPUs: 0}, "vcpus must be >= 1"},
		{"empty path", plain(""), "firmware path is required"},
		{"missing file", plain(filepath.Join(t.TempDir(), "absent.fd")), "read firmware"},
		{"empty image", plain(writeFirmware(t, nil)), "not a positive multiple"},
		{"unaligned image", plain(writeFirmware(t, fw[:len(fw)-1])), "not a positive multiple"},
		{"no footer table", plain(writeFirmware(t, make([]byte, PageSize))), "parse firmware"},
		{"no ASEV entry", plain(writeFirmware(t, stripSEVMetadataEntry(t, fw))), "no SEV metadata sections"},
		{
			"ASEV header starts before the image",
			plain(writeFirmware(t, patchFooterEntryData(t, fw, ovmf.OVMF_SEV_META_DATA_GUID, le32(2*PageSize)))),
			"malformed OVMF image",
		},
		{
			"footer table longer than the image",
			plain(writeFirmware(t, patchFooterEntrySize(t, fw, ovmf.OVMF_TABLE_FOOTER_GUID, 0xFFFF))),
			"malformed OVMF image",
		},
		{
			"no SEV-ES reset block",
			plain(writeFirmware(t, stripFooterEntry(t, fw, ovmf.SEV_ES_RESET_BLOCK_GUID))),
			"SEV-ES reset block",
		},
		{
			"unknown section type",
			plain(patched(ovmf.CPUID, func(s *ovmf.MetadataSection) { s.SectionTypeInt = 0x99 })),
			"unknown OVMF metadata section type",
		},
		{
			"memory section size not a page multiple",
			plain(patched(ovmf.SNPSECMEM, func(s *ovmf.MetadataSection) { s.Size++ })),
			"section at 0x800000",
		},
		{
			"unmeasured hashes section size not a page multiple",
			plain(patched(ovmf.SNPKernelHashes, func(s *ovmf.MetadataSection) { s.Size++ })),
			"section at 0x810000",
		},
		{
			"hashes section spans two pages",
			hashed(patched(ovmf.SNPKernelHashes, func(s *ovmf.MetadataSection) { s.Size = 2 * PageSize })),
			"kernel-hashes section is 8192 bytes",
		},
		{
			"no SEV_HASH_TABLE_RV entry",
			hashed(writeFirmware(t, stripFooterEntry(t, fw, ovmf.SEV_HASH_TABLE_RV_GUID))),
			"SEV_HASH_TABLE_RV",
		},
		{
			"SEV_HASH_TABLE_RV is zero",
			hashed(writeFirmware(t, patchFooterEntryData(t, fw, ovmf.SEV_HASH_TABLE_RV_GUID, le32(0)))),
			"SEV_HASH_TABLE_RV",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ld, err := LaunchDigest(tc.cfg)
			if err == nil {
				t.Fatalf("want error, got digest %x", ld)
			}
			if ld != nil {
				t.Errorf("digest %x returned alongside error %v", ld, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

// TestFirmwareDigestRejectsBadInput holds the cached, guest-independent prefix
// to the same fail-closed contract: a digest returned for an image that never
// parsed would seed every launch measurement built on top of it.
func TestFirmwareDigestRejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantErr string
	}{
		{"empty path", "", "firmware path is required"},
		{"missing file", filepath.Join(t.TempDir(), "absent.fd"), "read firmware"},
		{"empty image", writeFirmware(t, nil), "not a positive multiple"},
		{"no footer table", writeFirmware(t, make([]byte, PageSize)), "parse firmware"},
		{"no ASEV entry", writeFirmware(t, stripSEVMetadataEntry(t, readFixture(t))), "no SEV metadata sections"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ld, err := FirmwareDigest(tc.path)
			if err == nil {
				t.Fatalf("want error, got digest %x", ld)
			}
			if ld != nil {
				t.Errorf("digest %x returned alongside error %v", ld, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

// TestMustGUIDRejectsMalformed: a GUID that decoded to zeros instead of
// panicking would put the wrong header into the hash table page, moving every
// digest computed with kernel-hashes on.
func TestMustGUIDRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"not hex":   "9438d6zz-4f22-4cc9-b479-a793d411fd21",
		"odd chars": "9438d606-4f22-4cc9-b479-a793d411fd2",
		"too long":  "9438d606-4f22-4cc9-b479-a793d411fd2100",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("mustGUID(%q) returned a GUID instead of panicking", s)
				}
			}()
			_ = mustGUID(s)
		})
	}
}

// TestKernelHashesNeedSection guards the case where the firmware cannot carry
// the hash table: measuring it anyway would silently produce a digest no guest
// ever reports.
func TestKernelHashesNeedSection(t *testing.T) {
	stripped := writeFirmware(t, stripKernelHashesSection(t, readFixture(t)))
	kh := NewKernelHashes(nil, nil, "")
	sig, _ := VCPUSignatureByName("EPYC-v4")
	_, err := LaunchDigest(Config{FirmwarePath: stripped, KernelHashes: &kh, VCPUs: 1, VCPUSig: sig, GuestFeatures: 1})
	if err == nil || !strings.Contains(err.Error(), "SNP_KERNEL_HASHES") {
		t.Errorf("want SNP_KERNEL_HASHES error, got %v", err)
	}
}

// descriptorBytes is the on-disk form of an OVMF metadata descriptor.
func descriptorBytes(s ovmf.MetadataSection) []byte {
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:], s.GPA)
	binary.LittleEndian.PutUint32(b[4:], s.Size)
	binary.LittleEndian.PutUint32(b[8:], s.SectionTypeInt)
	return b[:]
}

// patchMetadataSection rewrites the first metadata descriptor of type st,
// producing an image that parses but describes something the real firmware
// never would.
func patchMetadataSection(t *testing.T, fw []byte, st ovmf.SectionType, edit func(*ovmf.MetadataSection)) []byte {
	t.Helper()
	parsed, err := openFirmware(writeFirmware(t, fw))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range parsed.MetadataItems() {
		if ovmf.SectionType(s.SectionTypeInt) != st {
			continue
		}
		idx := bytes.Index(fw, descriptorBytes(s))
		if idx < 0 {
			t.Fatalf("descriptor for section type %d not found", st)
		}
		edit(&s)
		out := bytes.Clone(fw)
		copy(out[idx:], descriptorBytes(s))
		return out
	}
	t.Fatalf("fixture has no section of type %d", st)
	return nil
}

// stripKernelHashesSection rewrites the SNP_KERNEL_HASHES descriptor into a
// plain memory section.
func stripKernelHashesSection(t *testing.T, fw []byte) []byte {
	t.Helper()
	return patchMetadataSection(t, fw, ovmf.SNPKernelHashes, func(s *ovmf.MetadataSection) {
		s.SectionTypeInt = uint32(ovmf.SNPSECMEM)
	})
}

// footerEntryHeaderSize is sizeof(struct { uint16 size; guid[16]; }).
const footerEntryHeaderSize = 18

// footerEntryGUID locates a footer table entry by GUID. Entries are stored
// backwards: payload, then a uint16 total size, then the GUID.
func footerEntryGUID(t *testing.T, fw []byte, guid string) int {
	t.Helper()
	g := mustGUID(guid)
	idx := bytes.Index(fw, g[:])
	if idx < 0 {
		t.Fatalf("fixture has no %s footer entry", guid)
	}
	return idx
}

// stripFooterEntry blanks a footer table GUID, leaving an image the upstream
// parser accepts but which no longer publishes that entry.
func stripFooterEntry(t *testing.T, fw []byte, guid string) []byte {
	t.Helper()
	idx := footerEntryGUID(t, fw, guid)
	out := bytes.Clone(fw)
	copy(out[idx:idx+16], make([]byte, 16))
	return out
}

// stripSEVMetadataEntry leaves an image the upstream parser accepts with zero
// metadata sections.
func stripSEVMetadataEntry(t *testing.T, fw []byte) []byte {
	t.Helper()
	return stripFooterEntry(t, fw, ovmf.OVMF_SEV_META_DATA_GUID)
}

// patchFooterEntryData overwrites the head of a footer entry's payload.
func patchFooterEntryData(t *testing.T, fw []byte, guid string, data []byte) []byte {
	t.Helper()
	idx := footerEntryGUID(t, fw, guid)
	size := int(binary.LittleEndian.Uint16(fw[idx-2:]))
	payload := idx - 2 - (size - footerEntryHeaderSize)
	if len(data) > size-footerEntryHeaderSize {
		t.Fatalf("%s payload is %d bytes, cannot write %d", guid, size-footerEntryHeaderSize, len(data))
	}
	out := bytes.Clone(fw)
	copy(out[payload:], data)
	return out
}

// patchFooterEntrySize overwrites a footer entry's declared total size.
func patchFooterEntrySize(t *testing.T, fw []byte, guid string, size uint16) []byte {
	t.Helper()
	idx := footerEntryGUID(t, fw, guid)
	out := bytes.Clone(fw)
	binary.LittleEndian.PutUint16(out[idx-2:], size)
	return out
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func sha256sumOf(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
