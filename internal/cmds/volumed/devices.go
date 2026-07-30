package volumed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// SerialPrefix precedes the volume name in a device's virtio-block serial.
// VIRTIO_BLK_ID_BYTES is 20, so this leaves 12 characters for the name — which
// is why `c8s volume create` caps it there.
const SerialPrefix = volume.SerialPrefix

// SysBlock is the sysfs directory listing block devices.
const SysBlock = "/sys/block"

// SerialDevices finds a volume's device by its virtio-block serial.
//
// The serial is read from sysfs rather than resolved through
// /dev/disk/by-id, which only exists where udev has run. This is the same
// signal the confos initrd matches on to find its scratch disk.
//
// The serial is a **selector, not a trust input**: the host chooses it, and
// answers the query per read. Naming the wrong device fails closed later — the
// key will not decrypt it, and verity will not accept it — so nothing here has
// to establish that the device is the right one, only which one was named.
type SerialDevices struct {
	// SysBlock is the sysfs block directory; empty means SysBlock.
	SysBlock string
	// DevDir is where the device nodes live; empty means "/dev".
	DevDir string
}

// Device returns the block device carrying the named volume.
//
// A serial matching more than one device is refused rather than resolved to
// whichever was read first: the host can attach two devices claiming the same
// serial, and picking one would make which volume a pod gets depend on scan
// order.
func (d SerialDevices) Device(name string) (string, error) {
	if err := ValidVolumeName(name); err != nil {
		return "", err
	}
	want := SerialPrefix + name

	entries, err := os.ReadDir(d.sysBlock())
	if err != nil {
		return "", fmt.Errorf("volumed: list block devices: %w", err)
	}
	var found []string
	for _, e := range entries {
		serial, err := os.ReadFile(filepath.Join(d.sysBlock(), e.Name(), "serial"))
		if err != nil {
			// A device without a serial is simply not a candidate.
			continue
		}
		if strings.TrimSpace(string(serial)) == want {
			found = append(found, e.Name())
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("volumed: no block device carries serial %s", want)
	case 1:
		return filepath.Join(d.devDir(), found[0]), nil
	default:
		return "", fmt.Errorf("volumed: %d block devices carry serial %s: %s",
			len(found), want, strings.Join(found, ", "))
	}
}

// ValidVolumeName reports whether name can be both a Kubernetes volume and a
// virtio serial. The webhook, the sidecar and this daemon all apply it, so a
// name accepted at admission is one the node can resolve to a device.
func ValidVolumeName(name string) error {
	if err := volume.ValidVolumeName(name); err != nil {
		return fmt.Errorf("volumed: %w", err)
	}
	return nil
}

func (d SerialDevices) sysBlock() string {
	if d.SysBlock != "" {
		return d.SysBlock
	}
	return SysBlock
}

func (d SerialDevices) devDir() string {
	if d.DevDir != "" {
		return d.DevDir
	}
	return "/dev"
}
