//go:build !linux

package fileutil

import "fmt"

// RequireRAMBacked fails closed off Linux: without statfs there is no way to
// prove dir is memory-backed, so secret staging is refused.
func RequireRAMBacked(dir string) error {
	return fmt.Errorf("cannot verify %s is RAM-backed: linux only", dir)
}
