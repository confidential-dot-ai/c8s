package volume

import (
	"fmt"
	"regexp"
)

// SerialPrefix precedes a volume name in its virtio-block serial.
const SerialPrefix = "c8s-vol-"

// KubeVolumePrefix precedes a volume name in the injected Kubernetes volume.
const KubeVolumePrefix = "c8s-volume-"

// maxNameLen is what remains of VIRTIO_BLK_ID_BYTES after SerialPrefix.
const maxNameLen = 20 - len(SerialPrefix)

var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidVolumeName reports whether name can be both a Kubernetes volume and a
// virtio-block serial without truncation.
func ValidVolumeName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("volume name %q is not a dns-1123 label", name)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("volume name %q is %d characters; the device serial holds %d",
			name, len(name), maxNameLen)
	}
	return nil
}

// KubeVolumeName is the Kubernetes volume carrying the named volume.
func KubeVolumeName(name string) string { return KubeVolumePrefix + name }
