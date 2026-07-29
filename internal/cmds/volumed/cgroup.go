// Package volumed implements the node agent that opens encrypted volumes for
// the pods entitled to them. See docs/volumes.md.
package volumed

import (
	"fmt"
	"os"
	"regexp"
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

// PodUIDCandidatesForPID returns every pod UID appearing in a process's cgroup
// file under procRoot (normally "/proc"), shallowest path component first,
// deduplicated and normalized to the dashed lowercase form Kubernetes uses.
//
// The caller MUST take the SHALLOWEST candidate, for the same reason
// workloadclaims.ContainerIDCandidatesForPID does: a process can only move
// itself DEEPER into cgroups it creates, so its runtime-assigned pod slice is
// always an ancestor of anything it nests beneath. A caller that picked the
// deepest could be handed a victim's UID by a process that created a child
// cgroup named after it — and here that would mount another pod's decrypted
// volume into the attacker's own directory.
func PodUIDCandidatesForPID(procRoot string, pid int) ([]string, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("volumed: no peer PID (caller not on a unix socket?)")
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", procRoot, pid))
	if err != nil {
		return nil, fmt.Errorf("volumed: read peer cgroup: %w", err)
	}
	var (
		candidates []string
		seen       = map[string]struct{}{}
	)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		for _, m := range podUIDPattern.FindAllStringSubmatch(line, -1) {
			uid := normalizePodUID(m[1])
			if _, dup := seen[uid]; dup {
				continue
			}
			seen[uid] = struct{}{}
			candidates = append(candidates, uid)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("volumed: peer pid %d has no pod cgroup", pid)
	}
	return candidates, nil
}

// normalizePodUID converts a cgroup-spelled UID to the form Kubernetes uses in
// the kubelet pod directory: lowercase, dash-separated. The systemd driver
// writes underscores, and the kubelet directory does not.
func normalizePodUID(raw string) string {
	return strings.ToLower(strings.ReplaceAll(raw, "_", "-"))
}
