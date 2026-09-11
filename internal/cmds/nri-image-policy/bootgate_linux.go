//go:build linux

package nriimagepolicy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// powerOff stops the node. The plugin is a containerd child running as root in
// the host namespaces, so the syscall is available to it; it is not to the
// chart's containerised deployment, where the boot gate is off.
//
// Power off rather than reboot: a node that booted into a state this check
// rejects would reboot into it again, and a stopped CVM is the failure mode
// the operator can see.
func powerOff() error {
	syscall.Sync()
	return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}
