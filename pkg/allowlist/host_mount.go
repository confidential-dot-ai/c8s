package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// HostSourceDigest commits to an exact clean absolute source path.
func HostSourceDigest(source string) string {
	if !path.IsAbs(source) || path.Clean(source) != source || strings.ContainsRune(source, 0) {
		return ""
	}
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:])
}
