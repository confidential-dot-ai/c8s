// Package kataspec reads the parts of kata-agent's on-disk container bundle
// that c8s makes trust decisions on.
//
// policy-monitor (image admission) and rtmr3-measurer (runtime measurement)
// both key off the same OCI spec at /run/kata-containers/<id>/config.json. They
// have to agree: a container one of them decides on and the other skips is a
// container whose measurement and whose admission disagree.
package kataspec

import "regexp"

// PullReferenceKey is the annotation kata's guest-pull handler builds its image
// reference from (handleImageGuestPullBlockVolume in the kata runtime). It is
// the only annotation the enforced digest may come from: the baked kata-agent
// policy requires the guest-pull storage's source to equal this string and to
// be digest-pinned, and that equality is what ties the digest c8s checks to the
// bytes the guest fetches. See c8s/docs/kata-image-policy.md.
const PullReferenceKey = "io.kubernetes.cri.image-name"

// pinnedReference matches a digest-pinned image reference. It is the Go side of
// the same anchor the baked policy applies to the guest-pull source; the two
// must accept the same set.
var pinnedReference = regexp.MustCompile(`^[^@]+@sha256:([0-9a-f]{64})$`)

// PullDigest returns the sha256 digest of the image the guest pulls for this
// container. Reports false when the reference is missing or carries a tag
// rather than a digest — a tag is resolved by the registry at pull time, so it
// names no particular bytes.
func PullDigest(annotations map[string]string) (string, bool) {
	m := pinnedReference.FindStringSubmatch(annotations[PullReferenceKey])
	if m == nil {
		return "", false
	}
	return "sha256:" + m[1], true
}

// containerTypeKeys mirrors kata-agent's K8S_CONTAINER_TYPE_KEYS: the
// annotation keys a CRI runtime marks a container's type with.
var containerTypeKeys = []string{
	"io.kubernetes.cri.container-type",  // containerd CRI
	"io.kubernetes.cri-o.ContainerType", // CRI-O
}

// IsSandbox reports whether the annotations mark this as the pod's sandbox
// (pause) container. It mirrors kata-agent's own is_sandbox() exactly, and that
// lockstep is load-bearing: in guest-pull mode kata runs the pause baked into
// the dm-verity rootfs for any container it deems a sandbox, so the set c8s
// exempts from digest enforcement must not be wider than kata's.
func IsSandbox(annotations map[string]string) bool {
	for _, key := range containerTypeKeys {
		if annotations[key] == "sandbox" {
			return true
		}
	}
	return false
}

// containerID is the id set the baked kata-agent policy admits. kata's own
// verify_id is wider (Unicode alphanumerics, no length bound); the policy
// narrows CreateContainerRequest to this so that every container the guest
// creates is one the watchers below resolve.
var containerID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$`)

// ReservedBundleNames are kata's own subdirectories of /run/kata-containers.
// They are not containers and never grow a config.json. The baked policy
// refuses them as container ids, so skipping them here cannot hide one.
var ReservedBundleNames = []string{"shared", "sandbox", "image"}

// ValidContainerID reports whether id is a container id c8s watches.
func ValidContainerID(id string) bool {
	for _, r := range ReservedBundleNames {
		if id == r {
			return false
		}
	}
	return containerID.MatchString(id)
}
