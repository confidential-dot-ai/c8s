// Package devmapper removes device-mapper targets via the DM ioctl surface on
// /dev/mapper/control. Used by the NRI reap path and by any node-side c8s
// caller that needs to close a dm target without shelling out to cryptsetup
// or dmsetup — c8s node images are debian-slim and the reap runs on hosts
// c8s does not require either binary on. See docs/pitfalls.md — LUKS leak.
//
// Only the two operations c8s reap needs are implemented: Remove and Exists.
// The ABI is documented in <linux/dm-ioctl.h>; the struct is a fixed 312-byte
// header + variable-length payload area. Removing a target needs only the
// header (name in [128]byte), so no payload handling.
package devmapper

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrNotFound is returned when the target does not exist (ENXIO from the ioctl).
// Callers reaping should treat it as a no-op.
var ErrNotFound = errors.New("device-mapper target not found")

// ErrBusy is returned when the target is still in use (EBUSY from the ioctl),
// e.g. the fs on top is still mounted somewhere. The caller must unmount first.
var ErrBusy = errors.New("device-mapper target busy")

const controlPath = "/dev/mapper/control"

// dmNameLen and dmUUIDLen from <linux/dm-ioctl.h>.
const (
	dmNameLen = 128
	dmUUIDLen = 129
)

// dmIoctl matches struct dm_ioctl in <linux/dm-ioctl.h>. Field order and sizes
// must not change: the kernel reads the header by offset.
type dmIoctl struct {
	Version     [3]uint32
	DataSize    uint32
	DataStart   uint32
	TargetCount uint32
	OpenCount   int32
	Flags       uint32
	EventNr     uint32
	Padding     uint32
	Dev         uint64
	Name        [dmNameLen]byte
	UUID        [dmUUIDLen]byte
	Data        [7]byte
}

// dmVersionMajor is the ABI version c8s targets. 4.x has been stable since
// Linux 2.6.31 and is what dm-crypt targets emit.
const dmVersionMajor uint32 = 4

// _IOWR(0xfd, 0, ...) etc. Encoded per Linux's asm-generic/ioctl.h; the same
// values on every arch c8s supports (amd64, arm64). Ioctl numbers depend only
// on the direction, type code (0xfd), request number, and struct size.
const (
	iocWrite     = 1
	iocRead      = 2
	iocReadWrite = iocRead | iocWrite

	iocNRBits   = 8
	iocTypeBits = 8
	iocSizeBits = 14

	iocNRShift   = 0
	iocTypeShift = iocNRShift + iocNRBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits

	dmIoctlType = 0xfd
	dmVersionNR = 0
	dmRemoveNR  = 4
	dmStatusNR  = 12
)

func iocEncode(dir, typ, nr, size uintptr) uintptr {
	return (dir << iocDirShift) | (typ << iocTypeShift) | (nr << iocNRShift) | (size << iocSizeShift)
}

var (
	sizeofDMIoctl = uintptr(unsafe.Sizeof(dmIoctl{}))
	dmRemoveIoctl = iocEncode(iocReadWrite, dmIoctlType, dmRemoveNR, sizeofDMIoctl)
	dmStatusIoctl = iocEncode(iocReadWrite, dmIoctlType, dmStatusNR, sizeofDMIoctl)
)

// Remove issues DM_DEV_REMOVE for the named target. ENXIO ⇒ ErrNotFound;
// EBUSY ⇒ ErrBusy; other errors are surfaced verbatim.
func Remove(name string) error {
	if len(name) >= dmNameLen {
		return fmt.Errorf("devmapper: name %q too long (max %d)", name, dmNameLen-1)
	}
	arg := dmIoctl{
		Version:  [3]uint32{dmVersionMajor, 0, 0},
		DataSize: uint32(sizeofDMIoctl),
	}
	copy(arg.Name[:], name)
	return ioctl(dmRemoveIoctl, &arg)
}

// Exists reports whether a target with the given name is currently active.
// Any error other than ErrNotFound is returned verbatim.
func Exists(name string) (bool, error) {
	if len(name) >= dmNameLen {
		return false, fmt.Errorf("devmapper: name %q too long", name)
	}
	arg := dmIoctl{
		Version:  [3]uint32{dmVersionMajor, 0, 0},
		DataSize: uint32(sizeofDMIoctl),
	}
	copy(arg.Name[:], name)
	err := ioctl(dmStatusIoctl, &arg)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

func ioctl(req uintptr, arg *dmIoctl) error {
	fd, err := unix.Open(controlPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", controlPath, err)
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(arg)))
	switch errno {
	case 0:
		return nil
	case unix.ENXIO, unix.ENOENT:
		return ErrNotFound
	case unix.EBUSY:
		return ErrBusy
	default:
		return fmt.Errorf("dm ioctl: %w", errno)
	}
}
