package fileutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// RequireRAMBacked fails unless dir sits on tmpfs or ramfs. Callers staging
// secrets (join tokens, private keys) use it to enforce "memory only" rather
// than merely documenting it: on any other filesystem the bytes are readable
// by the host.
func RequireRAMBacked(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	// f_type is a 32-bit magic; the field's signedness varies by GOARCH.
	if m := uint32(st.Type); m != uint32(unix.TMPFS_MAGIC) && m != uint32(unix.RAMFS_MAGIC) {
		return fmt.Errorf("%s is not RAM-backed (fs magic %#x)", dir, m)
	}
	return nil
}
