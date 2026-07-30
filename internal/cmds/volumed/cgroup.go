// Package volumed implements the node agent that opens encrypted volumes for
// the pods on it. See docs/volumes.md.
package volumed

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// podUIDPattern matches the pod UID a CRI runtime embeds in a container
// process's cgroup path, in both driver spellings:
//
//	systemd:  …/kubepods-burstable-pod<uid with underscores>.slice/…
//	cgroupfs: …/kubepods/burstable/pod<uid with dashes>/…
//
// The separator class covers both, because the systemd driver rewrites the
// UUID's dashes to underscores.
var podUIDPattern = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})`)

// PodCgroup is a pod as the kernel places it.
type PodCgroup struct {
	// UID names the pod's kubelet directory.
	UID string
	// Path is the pod's cgroup, from the cgroup root. Its removal is what tells
	// the reaper the pod is gone.
	Path string
}

// PodCandidatesForPID returns every pod appearing in a process's cgroup file
// under procRoot (normally "/proc"), shallowest path component first,
// deduplicated and normalized to the dashed lowercase form Kubernetes uses.
//
// The caller MUST take the SHALLOWEST candidate, for the same reason
// workloadclaims.ContainerIDCandidatesForPID does: a process can only move
// itself DEEPER into cgroups it creates, so its runtime-assigned pod slice is
// always an ancestor of anything it nests beneath. A caller that picked the
// deepest could be handed a victim's UID by a process that created a child
// cgroup named after it — and here that would mount another pod's decrypted
// volume into the attacker's own directory.
func PodCandidatesForPID(procRoot string, pid int) ([]PodCgroup, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("volumed: no peer PID (caller not on a unix socket?)")
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", procRoot, pid))
	if err != nil {
		return nil, fmt.Errorf("volumed: read peer cgroup: %w", err)
	}
	var (
		candidates []PodCgroup
		seen       = map[string]struct{}{}
	)
	for _, line := range unifiedFirst(strings.Split(strings.TrimSpace(string(data)), "\n")) {
		parts := strings.Split(cgroupPath(line), "/")
		for i, part := range parts {
			m := podUIDPattern.FindStringSubmatch(part)
			if m == nil {
				continue
			}
			uid := normalizePodUID(m[1])
			if _, dup := seen[uid]; dup {
				continue
			}
			seen[uid] = struct{}{}
			candidates = append(candidates, PodCgroup{UID: uid, Path: strings.Join(parts[:i+1], "/")})
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("volumed: peer pid %d has no pod cgroup", pid)
	}
	return candidates, nil
}

// cgroupPath is the path field of a "hierarchy-ID:controllers:path" line.
func cgroupPath(line string) string {
	fields := strings.SplitN(line, ":", 3)
	if len(fields) != 3 {
		return ""
	}
	return fields[2]
}

// unifiedFirst orders the cgroup v2 line ahead of any v1 ones, so Path is the
// one that joins onto a single cgroup root rather than a per-controller subtree.
func unifiedFirst(lines []string) []string {
	out := slices.Clone(lines)
	slices.SortStableFunc(out, func(a, b string) int { return unifiedRank(a) - unifiedRank(b) })
	return out
}

func unifiedRank(line string) int {
	if strings.HasPrefix(line, "0::") {
		return 0
	}
	return 1
}

// normalizePodUID converts a cgroup-spelled UID to the form Kubernetes uses in
// the kubelet pod directory: lowercase, dash-separated. The systemd driver
// writes underscores, and the kubelet directory does not.
func normalizePodUID(raw string) string {
	return strings.ToLower(strings.ReplaceAll(raw, "_", "-"))
}
