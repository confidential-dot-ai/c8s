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
	dir := t.TempDir()
	kernel := dir + "/vmlinuz"
	if err := os.WriteFile(kernel, []byte("FAKEKERNEL"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := KernelHashesFromFiles(kernel, "", "console=ttyS0 loglevel=7")
	if err != nil {
		t.Fatal(err)
	}
	want := NewKernelHashes([]byte("FAKEKERNEL"), nil, "console=ttyS0 loglevel=7")
	if *got != want {
		t.Error("KernelHashesFromFiles disagrees with NewKernelHashes")
	}
	if _, err := KernelHashesFromFiles(dir+"/absent", "", ""); err == nil {
		t.Error("missing kernel must fail")
	}
}

// TestLaunchDigestRejectsBadInput covers the malformed images upstream's parser
// indexes into without bounds checks, so a panic there surfaces as an error.
func TestLaunchDigestRejectsBadInput(t *testing.T) {
	fw := readFixture(t)
	cases := map[string]Config{
		"zero vcpus":             {FirmwarePath: fixture, VCPUs: 0},
		"missing file":           {FirmwarePath: filepath.Join(t.TempDir(), "absent.fd"), VCPUs: 1},
		"empty path":             {VCPUs: 1},
		"unaligned firmware":     {FirmwarePath: writeFirmware(t, fw[:len(fw)-1]), VCPUs: 1},
		"truncated firmware":     {FirmwarePath: writeFirmware(t, nil), VCPUs: 1},
		"firmware without table": {FirmwarePath: writeFirmware(t, make([]byte, PageSize)), VCPUs: 1},
		"firmware without ASEV":  {FirmwarePath: writeFirmware(t, stripSEVMetadataEntry(t, fw)), VCPUs: 1},
	}
	for name, cfg := range cases {
		if _, err := LaunchDigest(cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
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

// stripKernelHashesSection rewrites the SNP_KERNEL_HASHES descriptor into a
// plain memory section.
func stripKernelHashesSection(t *testing.T, fw []byte) []byte {
	t.Helper()
	parsed, err := openFirmware(writeFirmware(t, fw))
	if err != nil {
		t.Fatal(err)
	}
	out := bytes.Clone(fw)
	for _, s := range parsed.MetadataItems() {
		if ovmf.SectionType(s.SectionTypeInt) != ovmf.SNPKernelHashes {
			continue
		}
		// Locate the descriptor by scanning for its gpa/size/type triple.
		var want [12]byte
		binary.LittleEndian.PutUint32(want[0:], s.GPA)
		binary.LittleEndian.PutUint32(want[4:], s.Size)
		binary.LittleEndian.PutUint32(want[8:], s.SectionTypeInt)
		idx := bytes.Index(out, want[:])
		if idx < 0 {
			t.Fatal("SNP_KERNEL_HASHES descriptor not found")
		}
		binary.LittleEndian.PutUint32(out[idx+8:], uint32(ovmf.SNPSECMEM))
		return out
	}
	t.Fatal("fixture has no SNP_KERNEL_HASHES section")
	return nil
}

// stripSEVMetadataEntry blanks the OVMF_SEV_META_DATA GUID in the footer table,
// leaving an image the upstream parser accepts with zero metadata sections.
func stripSEVMetadataEntry(t *testing.T, fw []byte) []byte {
	t.Helper()
	guid := mustGUID(ovmf.OVMF_SEV_META_DATA_GUID)
	idx := bytes.Index(fw, guid[:])
	if idx < 0 {
		t.Fatal("fixture has no OVMF_SEV_META_DATA entry")
	}
	out := bytes.Clone(fw)
	copy(out[idx:idx+16], make([]byte, 16))
	return out
}

func sha256sumOf(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
