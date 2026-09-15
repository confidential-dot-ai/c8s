package launchdata

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// launchDataHeader is the first line of every launchdata v1 manifest.
const launchDataHeader = "confai-launchdata v1\n"

var launchDataFilename = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// LaunchDataManifest renders the canonical launchdata v1 manifest over dir's
// top-level regular files: the header line, then one
// "<sha256 hex>  <filename>\n" line per file, sorted by filename byte order
// (LC_ALL=C). Dotfiles are skipped; any other non-regular entry
// (subdirectory, symlink, device) is an error, as is a dir with no files —
// an empty commitment binds nothing. The same text is built by the launchdata
// ISO tooling on the host and by the guest before any service starts, so the
// rendering here must never drift.
func LaunchDataManifest(dir string) ([]byte, error) {
	manifest, _, err := readLaunchData(dir)
	return manifest, err
}

// LoadLaunchData returns the manifest and the exact operator-pubkey bytes hashed into it.
func LoadLaunchData(dir string) (manifest, operatorPubkey []byte, err error) {
	manifest, operatorPubkey, err = readLaunchData(dir)
	if err != nil {
		return nil, nil, err
	}
	if len(operatorPubkey) == 0 {
		return nil, nil, fmt.Errorf("%s/operator-pubkey is missing or empty", dir)
	}
	return manifest, operatorPubkey, nil
}

func readLaunchData(dir string) ([]byte, []byte, error) {
	entries, err := os.ReadDir(dir) // sorted by filename
	if err != nil {
		return nil, nil, fmt.Errorf("read launchdata dir: %w", err)
	}
	var operatorPubkey []byte
	var buf bytes.Buffer
	buf.WriteString(launchDataHeader)
	files := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !e.Type().IsRegular() {
			return nil, nil, fmt.Errorf("launchdata dir %s: %q is not a regular file", dir, name)
		}
		if !launchDataFilename.MatchString(name) {
			// The ISO tooling and the guest enforce the same name charset;
			// anything else could render an ambiguous manifest line.
			return nil, nil, fmt.Errorf("launchdata dir %s: %q contains characters outside [A-Za-z0-9._-]", dir, name)
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, nil, fmt.Errorf("read launchdata file: %w", err)
		}
		if name == "operator-pubkey" {
			operatorPubkey = data
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&buf, "%s  %s\n", hex.EncodeToString(sum[:]), name)
		files++
	}
	if files == 0 {
		return nil, nil, fmt.Errorf("launchdata dir %s has no files to commit", dir)
	}
	return buf.Bytes(), operatorPubkey, nil
}

// LaunchDataHostData computes the SNP launch-time launchdata binding: the
// value the launcher commits as HOSTDATA when launching a node CVM with this
// launchdata ISO:
//
//	HOSTDATA = SHA256(manifest)
//
// The guest fail-closes unless its report's HOSTDATA equals this value.
func LaunchDataHostData(manifest []byte) [sha256.Size]byte {
	return sha256.Sum256(manifest)
}

// LaunchDataMRConfigID computes the TDX launch-time launchdata binding: the
// value the launcher commits as MRCONFIGID when launching a node TD with
// this launchdata ISO:
//
//	MRCONFIGID = SHA384(manifest)
//
// The guest fail-closes unless its report's MRCONFIGID equals this value.
func LaunchDataMRConfigID(manifest []byte) [sha512.Size384]byte {
	return sha512.Sum384(manifest)
}
