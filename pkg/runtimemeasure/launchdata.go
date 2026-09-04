package runtimemeasure

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// launchDataHeader is the first line of every launchdata v1 manifest.
const launchDataHeader = "confai-launchdata v1\n"

// LaunchDataManifest renders the canonical launchdata v1 manifest over dir's
// top-level regular files: the header line, then one
// "<sha256 hex>  <filename>\n" line per file, sorted by filename byte order
// (LC_ALL=C). Dotfiles are skipped; any other non-regular entry
// (subdirectory, symlink, device) is an error, as is a dir with no files —
// an empty commitment binds nothing. The same text is built by the launchdata
// ISO tooling on the host and by the guest before any service starts, so the
// rendering here must never drift.
func LaunchDataManifest(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir) // sorted by filename
	if err != nil {
		return nil, fmt.Errorf("read launchdata dir: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(launchDataHeader)
	files := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("launchdata dir %s: %q is not a regular file", dir, name)
		}
		if strings.ContainsFunc(name, func(r rune) bool {
			return r != '.' && r != '_' && r != '-' &&
				(r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
		}) {
			// The ISO tooling and the guest enforce the same name charset;
			// anything else could render an ambiguous manifest line.
			return nil, fmt.Errorf("launchdata dir %s: %q contains characters outside [A-Za-z0-9._-]", dir, name)
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read launchdata file: %w", err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&buf, "%s  %s\n", hex.EncodeToString(sum[:]), name)
		files++
	}
	if files == 0 {
		return nil, fmt.Errorf("launchdata dir %s has no files to commit", dir)
	}
	return buf.Bytes(), nil
}

// LaunchDataHostData computes the SNP launch-time launchdata binding: the
// value the launcher commits as HOSTDATA when launching a node CVM with this
// launchdata ISO:
//
//	HOSTDATA = SHA256(manifest)
//
// The guest fail-closes unless its report's HOSTDATA equals this value.
func LaunchDataHostData(manifest []byte) [HostDataSize]byte {
	return sha256.Sum256(manifest)
}

// LaunchDataRTMR3Digest computes the TDX launchdata event: SHA384(manifest),
// the value the guest extends into RTMR[3] before any service starts. The
// expected register value after that extend alone is
// Extend(Zero, LaunchDataRTMR3Digest(manifest)).
func LaunchDataRTMR3Digest(manifest []byte) [Size]byte {
	return sha512.Sum384(manifest)
}
