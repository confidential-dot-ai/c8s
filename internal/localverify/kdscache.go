package localverify

import (
	"os"
	"path/filepath"
)

// kdsCacheDirEnv overrides the on-disk VCEK cache location; an empty value
// disables the cache.
const kdsCacheDirEnv = "C8S_KDS_CACHE_DIR"

// defaultKDSCacheDir resolves the cache directory: the env override (empty
// disables), else the user cache dir, else none.
func defaultKDSCacheDir() string {
	if v, ok := os.LookupEnv(kdsCacheDirEnv); ok {
		return v
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "c8s", "kds")
}
