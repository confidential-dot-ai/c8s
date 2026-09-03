package policymeasure

import "golang.org/x/sys/unix"

// mountISO and unmountISO attach the policydata ISO read-only, with device
// nodes, setuid bits and execution refused: the disk is host-controlled
// data, never code. Vars so tests substitute a directory copy.
var (
	mountISO = func(dev, target string) error {
		return unix.Mount(dev, target, "iso9660", unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "")
	}
	unmountISO = func(target string) error {
		return unix.Unmount(target, 0)
	}
)
