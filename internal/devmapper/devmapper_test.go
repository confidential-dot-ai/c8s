package devmapper

import (
	"testing"
	"unsafe"
)

// TestDMIoctlLayout pins the wire ABI. If the kernel struct ever changes size
// or field alignment the ioctl numbers computed from sizeofDMIoctl move too,
// and the reap silently starts failing on a running host. Fail loudly here.
func TestDMIoctlLayout(t *testing.T) {
	var d dmIoctl
	// From <linux/dm-ioctl.h>: 3*4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + 128 + 129 + 7 = 312.
	// Go aligns the [7]byte tail on an 8-byte boundary because Dev is uint64;
	// 128 + 129 = 257 → +7 = 264, so the sum is 12+4+4+4+4+4+4+4+8+128+129+7 = 312 (no padding).
	if got := unsafe.Sizeof(d); got != 312 {
		t.Fatalf("sizeof(dmIoctl) = %d, want 312 (ABI mismatch — kernel struct dm_ioctl)", got)
	}
	// _IOWR(0xfd, 4, struct dm_ioctl) on Linux/amd64 with 312 bytes:
	//   dir (3) << 30 | size (312) << 16 | type (0xfd) << 8 | nr (4)
	//   = 0xc0000000 | 0x01380000 | 0x0000fd00 | 0x00000004 = 0xc138fd04
	if got := dmRemoveIoctl; got != 0xc138fd04 {
		t.Fatalf("DM_DEV_REMOVE ioctl = %#x, want 0xc138fd04", got)
	}
	if got := dmStatusIoctl; got != 0xc138fd0c {
		t.Fatalf("DM_DEV_STATUS ioctl = %#x, want 0xc138fd0c", got)
	}
}

// TestNameTooLong guards the client-side length check. The kernel would
// otherwise scribble past the Name field into UUID.
func TestNameTooLong(t *testing.T) {
	long := make([]byte, dmNameLen)
	for i := range long {
		long[i] = 'x'
	}
	if err := Remove(string(long)); err == nil {
		t.Fatal("Remove of over-length name must fail before ioctl")
	}
	if _, err := Exists(string(long)); err == nil {
		t.Fatal("Exists of over-length name must fail before ioctl")
	}
}
