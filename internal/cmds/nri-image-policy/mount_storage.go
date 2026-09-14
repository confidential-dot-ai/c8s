package nriimagepolicy

import "github.com/confidential-dot-ai/c8s/pkg/allowlist"

// mountStorage proves whether a volume is memory-backed or uses a c8s
// dm-crypt mapping. An unknown backing device is never treated as encrypted.
var mountStorage = detectMountStorage

var _ func(string) allowlist.MountStorage = mountStorage
