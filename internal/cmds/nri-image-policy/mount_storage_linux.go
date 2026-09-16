//go:build linux

package nriimagepolicy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const overlayFSMagic int64 = 0x794c7630

// scratchDiskSerial must match the scratch disk serial expected by
// confidential-os-builder's initrd; changes require coordination with that repo.
const scratchDiskSerial = "confai-scratch"

type linuxStorageInspector struct {
	sysDevBlock    string
	sysClassBlock  string
	mountInfo      string
	provenanceFile string
	bootIDFile     string
}

func newMountStorageInspector() mountStorageInspector {
	return linuxStorageInspector{
		sysDevBlock: "/sys/dev/block", sysClassBlock: "/sys/class/block",
		mountInfo: "/proc/self/mountinfo", provenanceFile: "/run/c8s/scratch-provenance.json",
		bootIDFile: "/proc/sys/kernel/random/boot_id",
	}
}

func (i linuxStorageInspector) Inspect(source string) allowlist.MountStorage {
	return i.inspect(source, map[string]bool{})
}

func (i linuxStorageInspector) inspect(source string, seen map[string]bool) allowlist.MountStorage {
	clean := filepath.Clean(source)
	if seen[clean] {
		return allowlist.MountUnknown
	}
	seen[clean] = true
	var fs unix.Statfs_t
	if err := unix.Statfs(clean, &fs); err != nil {
		return allowlist.MountUnknown
	}
	if fs.Type == unix.TMPFS_MAGIC {
		return allowlist.MountMemory
	}
	if fs.Type == overlayFSMagic {
		upper, ok := overlayUpperDir(i.mountInfo, clean)
		if !ok {
			return allowlist.MountUnknown
		}
		return i.inspect(upper, seen)
	}
	var st unix.Stat_t
	if err := unix.Stat(clean, &st); err != nil {
		return allowlist.MountUnknown
	}
	dev := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	if i.trustedEncryptedDevice(filepath.Join(i.sysDevBlock, dev), map[string]bool{}) {
		return allowlist.MountEncrypted
	}
	return allowlist.MountUnknown
}

// trustedEncryptedDevice accepts c8s volume mappings and the existing measured
// initrd scratch contract. The latter needs all three facts: exact mapper name,
// a crypt target UUID, and a backing virtio device whose exact serial is the
// launch contract. A host-controlled serial by itself is never sufficient.
func (i linuxStorageInspector) trustedEncryptedDevice(device string, seen map[string]bool) bool {
	real, err := filepath.EvalSymlinks(device)
	if err != nil {
		return false
	}
	if seen[real] {
		return false
	}
	seen[real] = true
	name := readTrim(filepath.Join(real, "dm/name"))
	uuid := readTrim(filepath.Join(real, "dm/uuid"))
	if strings.HasPrefix(uuid, "CRYPT-") {
		if strings.HasPrefix(name, "c8s-crypt-") {
			return true
		}
		if name == "scratch" && i.trustedScratchProvenance(real, uuid) && i.hasScratchSlave(real, map[string]bool{}) {
			return true
		}
	}
	entries, err := os.ReadDir(filepath.Join(real, "slaves"))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		return i.trustedEncryptedDevice(filepath.Join(real, "slaves", entry.Name()), seen)
	})
}

type scratchProvenance struct {
	Version int    `json:"version"`
	BootID  string `json:"boot_id"`
	Device  string `json:"device"`
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
}

func (i linuxStorageInspector) trustedScratchProvenance(device, uuid string) bool {
	b, err := os.ReadFile(i.provenanceFile)
	if err != nil {
		return false
	}
	var p scratchProvenance
	if json.Unmarshal(b, &p) != nil || p.Version != 1 || p.Name != "scratch" || p.UUID != uuid {
		return false
	}
	return p.BootID != "" && p.BootID == readTrim(i.bootIDFile) && p.Device != "" && p.Device == readTrim(filepath.Join(device, "dev"))
}

func (i linuxStorageInspector) hasScratchSlave(device string, seen map[string]bool) bool {
	real, err := filepath.EvalSymlinks(device)
	if err != nil || seen[real] {
		return false
	}
	seen[real] = true
	base := filepath.Base(real)
	if readTrim(filepath.Join(i.sysClassBlock, base, "device/serial")) == scratchDiskSerial {
		return true
	}
	entries, err := os.ReadDir(filepath.Join(real, "slaves"))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		return i.hasScratchSlave(filepath.Join(real, "slaves", entry.Name()), seen)
	})
}

func readTrim(name string) string {
	b, _ := os.ReadFile(name)
	return strings.TrimSpace(string(b))
}

// overlayUpperDir returns the writable backing directory of the most specific
// mount containing source, if that mount is a writable overlay.
//
// For example, source /var/lib/kubelet/pods/pod-a may sit under an overlay mounted
// at /var with upperdir=/scratch/var-upper. The containing mountpoint is /var;
// the returned directory is /scratch/var-upper, whose storage we inspect.
// If /var/lib is a separate mount, it hides the /var overlay for this source.
// We must use /var/lib's upperdir, or return false if it has none.
//
// mountinfo escapes spaces and a few control characters as octal sequences,
// which unescapeMountInfo handles.
func overlayUpperDir(mountInfo, source string) (string, bool) {
	f, err := os.Open(mountInfo)
	if err != nil {
		return "", false
	}
	defer f.Close()
	containingMountpoint, overlayUpper := "", ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		left, right, ok := strings.Cut(s.Text(), " - ")
		if !ok {
			continue
		}
		fields, post := strings.Fields(left), strings.Fields(right)
		if len(fields) < 5 || len(post) < 3 {
			continue
		}
		mountpoint := unescapeMountInfo(fields[4])
		if source != mountpoint && !strings.HasPrefix(source, strings.TrimSuffix(mountpoint, "/")+"/") {
			continue
		}
		if len(mountpoint) > len(containingMountpoint) {
			// A nested mount hides its ancestor, even when it cannot provide
			// an overlay upperdir whose storage we can verify.
			containingMountpoint, overlayUpper = mountpoint, ""
			if post[0] == "overlay" {
				overlayUpper = unescapeMountInfo(optionValue(post[2], "upperdir"))
			}
		}
	}
	return overlayUpper, s.Err() == nil && overlayUpper != ""
}

func optionValue(options, name string) string {
	for option := range strings.SplitSeq(options, ",") {
		if value, ok := strings.CutPrefix(option, name+"="); ok {
			return value
		}
	}
	return ""
}

func unescapeMountInfo(s string) string {
	// Octal escapes for space, tab, newline, and backslash, respectively.
	for _, code := range []string{"040", "011", "012", "134"} {
		value, _ := strconv.ParseInt(code, 8, 8)
		s = strings.ReplaceAll(s, `\`+code, string(rune(value)))
	}
	return s
}
