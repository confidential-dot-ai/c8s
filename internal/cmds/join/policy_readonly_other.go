//go:build !linux

package join

import "fmt"

// c8s node join runs on Linux. Refuse policy-file mode on other build targets
// instead of silently accepting a policy whose mount immutability we cannot
// establish with the Linux VFS flags.
var policyFileReadOnly = func(path string) error {
	return fmt.Errorf("cannot verify that %s is on a read-only filesystem on this platform", path)
}
