package workloadclaims

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// containerIDPattern matches the 64-hex container ID that CRI runtimes embed
// in a container process's cgroup path — both the systemd driver form
// (…/cri-containerd-<id>.scope) and the cgroupfs form (…/kubepods/…/<id>).
var containerIDPattern = regexp.MustCompile(`([0-9a-f]{64})`)

// ContainerIDCandidatesForPID returns every 64-hex component of a process's
// cgroup file under procRoot (normally "/proc"), in shallowest-to-deepest path
// order, deduplicated. This is the kernel-derived half of caller binding:
// SO_PEERCRED names the PID, the cgroup names the container, and the runtime's
// own state names the pod — nothing the caller sends is trusted.
//
// The caller (the broker) MUST resolve the SHALLOWEST candidate that is a
// tracked container, not the deepest. A process can only ever move itself
// DEEPER into cgroups it creates, so its runtime-assigned container scope is
// always an ancestor (shallower) of any child cgroup it nests — including one
// it maliciously names with a victim's container ID. Picking the shallowest
// tracked ID therefore returns the caller's own container and skips both a
// nested victim ID and CRI-O's untracked parent sandbox ID.
func ContainerIDCandidatesForPID(procRoot string, pid int) ([]string, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("workloadclaims: no peer PID (caller not on a unix socket?)")
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", procRoot, pid))
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: read peer cgroup: %w", err)
	}
	var candidates []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		for _, id := range containerIDPattern.FindAllString(line, -1) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("workloadclaims: peer pid %d has no container cgroup", pid)
	}
	return candidates, nil
}
