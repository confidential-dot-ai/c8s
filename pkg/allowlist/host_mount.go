package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

// HostSourceDigest commits to an exact clean absolute source path.
func HostSourceDigest(source string) (string, error) {
	if !path.IsAbs(source) || path.Clean(source) != source || strings.ContainsRune(source, 0) {
		return "", fmt.Errorf("host source %q must be a clean absolute path without NUL bytes", source)
	}
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:]), nil
}
