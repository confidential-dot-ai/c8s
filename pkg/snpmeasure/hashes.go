package snpmeasure

import "crypto/sha256"

// GUIDs of QEMU's kernel-hashes table, which OVMF looks up to verify the
// directly-loaded kernel, initrd and command line.
var (
	guidHashTable   = mustGUID("9438d606-4f22-4cc9-b479-a793d411fd21")
	guidHashKernel  = mustGUID("4de79437-abd2-427f-b835-d5b172d2045b")
	guidHashInitrd  = mustGUID("44baf731-3a2f-4bd7-9af1-41e29169781d")
	guidHashCmdline = mustGUID("97d02dd8-bd20-4c94-aa78-e7714d36ab2a")
)

const (
	// hashEntrySize is sizeof(struct { guid[16]; uint16 length; sha256[32]; }).
	hashEntrySize = 16 + 2 + sha256.Size
	// hashTableSize is the header plus the cmdline, initrd and kernel entries.
	hashTableSize = 16 + 2 + 3*hashEntrySize
	// hashTablePadded rounds the table up to 16-byte alignment. The header's
	// own length field still reports hashTableSize.
	hashTablePadded = (hashTableSize + 15) &^ 15
)

// table serialises the hash table exactly as QEMU writes it. Entry order is
// cmdline, initrd, kernel; any other order changes the measured page.
func (k *KernelHashes) table() []byte {
	b := make([]byte, hashTablePadded)
	copy(b, guidHashTable[:])
	putU16(b[16:], hashTableSize)
	at := 18
	for _, e := range []struct {
		guid [16]byte
		hash [sha256.Size]byte
	}{
		{guidHashCmdline, k.Cmdline},
		{guidHashInitrd, k.Initrd},
		{guidHashKernel, k.Kernel},
	} {
		copy(b[at:], e.guid[:])
		putU16(b[at+16:], hashEntrySize)
		copy(b[at+18:], e.hash[:])
		at += hashEntrySize
	}
	return b
}

// page places the table at offset within an otherwise-zero guest page. The
// offset comes from OVMF's SEV_HASH_TABLE_RV entry, not from the metadata
// section that names the page.
func (k *KernelHashes) page(offset uint64) []byte {
	p := make([]byte, PageSize)
	copy(p[offset:], k.table())
	return p
}
