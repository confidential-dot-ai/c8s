//go:build linux

package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func detectMountStorage(source string) allowlist.MountStorage {
	var fs unix.Statfs_t
	if err := unix.Statfs(source, &fs); err != nil {
		return allowlist.MountUnknown
	}
	if fs.Type == unix.TMPFS_MAGIC {
		return allowlist.MountMemory
	}
	var st unix.Stat_t
	if err := unix.Stat(source, &st); err != nil {
		return allowlist.MountUnknown
	}
	device := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	if hasC8sCryptDevice(filepath.Join("/sys/dev/block", device), map[string]bool{}) {
		return allowlist.MountEncrypted
	}
	return allowlist.MountUnknown
}

// A c8s immutable volume may put dm-verity above dm-crypt, so descend the
// device-mapper slave graph instead of checking only the filesystem device.
func hasC8sCryptDevice(device string, seen map[string]bool) bool {
	if seen[device] {
		return false
	}
	seen[device] = true
	name, err := os.ReadFile(filepath.Join(device, "dm/name"))
	if err == nil && strings.HasPrefix(strings.TrimSpace(string(name)), "c8s-crypt-") {
		uuid, err := os.ReadFile(filepath.Join(device, "dm/uuid"))
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
			return true
		}
	}
	slaves, err := os.ReadDir(filepath.Join(device, "slaves"))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(slaves, func(slave os.DirEntry) bool {
		return hasC8sCryptDevice(filepath.Join(device, "slaves", slave.Name()), seen)
	})
}
