package nriimagepolicy

import (
	"fmt"
	"strings"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The node's own staging paths. A mount's source says who chose the bytes
// behind it, which a destination alone cannot: a ConfigMap and an emptyDir land
// at whatever path the pod spec picks, and only the source tells them apart.
//
// kubeletRoot is the kubelet --root-dir. RKE2 leaves it at the upstream
// default and the node image does not override it (no kubelet-arg root-dir in
// node-guest-image/c8s/mkosi.extra/etc/rancher/rke2/config.yaml), so it is a
// constant here rather than a setting an operator could point elsewhere.
const (
	kubeletRoot = "/var/lib/kubelet"
	// podVolumeSegment precedes <plugin>/<volume name> under a pod's directory.
	podVolumeSegment = "/volumes/"
	// sandboxSegment appears in containerd's per-sandbox directory, under
	// whichever root and state dir containerd was configured with. Matching the
	// segment rather than an absolute prefix keeps this independent of that.
	sandboxSegment = "/io.containerd.grpc.v1.cri/sandboxes/"
	// emptyDirPlugin names the kubelet volume plugin directory for emptyDir.
	emptyDirPlugin = "kubernetes.io~empty-dir"
	// projectedPlugin names it for projected volumes, which is how the kubelet
	// delivers the serviceaccount token.
	projectedPlugin = "kubernetes.io~projected"
)

// serviceAccountDestination is where the kubelet projects a pod's API
// credentials. Every pod with a service account gets one and no entry declares
// it, so it is platform rather than operator content — at that destination and
// no other.
const serviceAccountDestination = "/var/run/secrets/kubernetes.io/serviceaccount"

// platformDestinations are the destinations the node fills for every pod. A
// mount is platform only when its source is node-staged AND it lands on one of
// these: a node-staged file bound anywhere else is the redirect this check
// exists to refuse.
var platformDestinations = map[string]bool{
	"/etc/hosts":           true,
	"/etc/hostname":        true,
	"/etc/resolv.conf":     true,
	"/dev/termination-log": true,
	"/dev/shm":             true,
}

// observeMounts classifies a container's bind mounts for the allowlist matcher.
//
// Non-bind entries are dropped: a source that is not an absolute path names a
// filesystem type (proc, sysfs, tmpfs, devpts, mqueue, cgroup) and carries
// nothing in.
func observeMounts(ctr *api.Container) []allowlist.ObservedMount {
	var out []allowlist.ObservedMount
	for _, m := range ctr.GetMounts() {
		source, destination := m.GetSource(), m.GetDestination()
		if !strings.HasPrefix(source, "/") {
			continue
		}
		class := classifyMount(destination, source)
		if class == allowlist.MountHost && floorPinsHostMount(ctr, m) {
			// The floor pinned this source, so it is not the sandbox rule's
			// business. Dropping it rather than relabelling it keeps "platform"
			// meaning "the node made this for every pod".
			continue
		}
		out = append(out, allowlist.ObservedMount{Destination: destination, Source: source, Class: class})
	}
	return out
}

// floorPinsHostMount reports whether a node-TCB floor rule pins this mount's
// source for this container, which is the only way a host path reaches a
// container the allowlist admits.
//
// It is the single seam the floor exception attaches to. Nothing is floor yet —
// the marker and its fixed privilege policy land separately — so every host
// source is refused today. See docs/allowlist-and-capabilities.md.
func floorPinsHostMount(_ *api.Container, _ *api.Mount) bool { return false }

// classifyMount attributes one bind mount by the path the node staged its
// source at. It is fail-closed by construction: every shape it does not
// recognise is MountHost, which no sandboxed entry admits.
func classifyMount(destination, source string) allowlist.MountClass {
	if plugin, ok := kubeletVolumePlugin(source); ok {
		switch {
		case plugin == emptyDirPlugin:
			return allowlist.MountEmptyDir
		case plugin == projectedPlugin && destination == serviceAccountDestination:
			return allowlist.MountPlatform
		default:
			return allowlist.MountData
		}
	}
	if !nodeStaged(source) {
		return allowlist.MountHost
	}
	if platformDestinations[destination] {
		return allowlist.MountPlatform
	}
	// Node-staged but landing somewhere the node never puts it: a subPath of an
	// operator volume (<pod>/volume-subpaths/...), or a platform file redirected
	// over an image path. Both are operator-chosen content.
	return allowlist.MountData
}

// kubeletVolumePlugin returns the volume plugin directory name of a source the
// kubelet staged for a pod volume — "kubernetes.io~configmap" and the like.
func kubeletVolumePlugin(source string) (string, bool) {
	rest, ok := strings.CutPrefix(source, kubeletRoot+"/pods/")
	if !ok {
		return "", false
	}
	_, rest, ok = strings.Cut(rest, podVolumeSegment)
	if !ok {
		return "", false
	}
	plugin, _, _ := strings.Cut(rest, "/")
	if plugin == "" {
		return "", false
	}
	return plugin, true
}

// nodeStaged reports whether a source is one the node writes itself rather than
// one a pod spec named: the kubelet's per-pod directory (etc-hosts, the
// per-container termination log, volume subpaths) and containerd's per-sandbox
// directory (hostname, resolv.conf, shm).
func nodeStaged(source string) bool {
	return strings.HasPrefix(source, kubeletRoot+"/pods/") || strings.Contains(source, sandboxSegment)
}

// mountObservation renders a classified mount table for a deny log: every bind
// mount with its source and class, so a reviewer can write the rule that would
// have admitted it. Node-local — it never reaches the denial reason, which a
// namespace reader sees.
func mountObservation(mounts []allowlist.ObservedMount) []string {
	out := make([]string, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, fmt.Sprintf("%s <- %s (%s)", m.Destination, m.Source, m.Class))
	}
	return out
}
