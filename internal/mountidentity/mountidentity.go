// Package mountidentity reads kernel mount data for a bind source.
package mountidentity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Evidence is the kernel identity that policy uses for a bind source.
type Evidence struct {
	Filesystem int64
	Mountpoint bool
	Canonical  bool
}

// Observe reports the filesystem and whether path is an exact kernel mount
// point. Canonical is false for a symlinked source path.
func Observe(path string) (Evidence, error) {
	clean := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return Evidence{}, err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(resolved, &stat); err != nil {
		return Evidence{}, err
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return Evidence{}, err
	}
	defer f.Close()

	evidence := Evidence{Filesystem: int64(stat.Type), Canonical: clean == resolved}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		if unescapeMountInfo(fields[4]) == resolved {
			evidence.Mountpoint = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return Evidence{}, fmt.Errorf("read mountinfo: %w", err)
	}
	return evidence, nil
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(value)
}
