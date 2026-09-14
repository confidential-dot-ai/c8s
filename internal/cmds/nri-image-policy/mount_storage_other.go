//go:build !linux

package nriimagepolicy

import "github.com/confidential-dot-ai/c8s/pkg/allowlist"

// Mount backing classification depends on Linux statfs and sysfs metadata.
func detectMountStorage(string) allowlist.MountStorage {
	return allowlist.MountUnknown
}
