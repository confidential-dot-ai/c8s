//go:build linux

package join

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// policyFileReadOnly makes policy-file mode safe for a node image: the file
// must live in an immutable rootfs or another read-only mount. A host-owned
// writable bind mount could otherwise replace the list of nodes allowed to
// receive the RKE2 agent token after the guest has been measured.
var policyFileReadOnly = requireReadOnlyPolicyFile

func requireReadOnlyPolicyFile(path string) error {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Flags&unix.ST_RDONLY == 0 {
		return fmt.Errorf("%s is on a writable mount", path)
	}
	return nil
}
