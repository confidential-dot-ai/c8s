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

// The container-type markers the baked kata-agent policy conjoins in its
// sandbox_annotations rule.
const (
	kataContainerTypeKey = "io.katacontainers.pkg.oci.container_type"
	criContainerTypeKey  = "io.kubernetes.cri.container-type"
)

// IsSandbox reports whether the annotations mark this as the pod's sandbox
// (pause) container. It mirrors the baked kata-agent policy's
// sandbox_annotations rule, and the lockstep is load-bearing: in guest-pull
// mode kata runs the pause baked into the dm-verity rootfs for any container
// that rule accepts, so the set c8s exempts from digest enforcement must not
// be wider. policy_lockstep_test.go machine-compares the two predicates.
func IsSandbox(annotations map[string]string) bool {
	return annotations[kataContainerTypeKey] == "pod_sandbox" &&
		annotations[criContainerTypeKey] == "sandbox"
}

// containerID is the id set the baked kata-agent policy admits: the 32 random
// bytes containerd's CRI and CRI-O hex-encode into a container or sandbox id.
var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidContainerID reports whether id is a container id c8s watches.
func ValidContainerID(id string) bool {
	return containerID.MatchString(id)
}
