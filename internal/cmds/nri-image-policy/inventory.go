package nriimagepolicy

import (
	"fmt"
	"slices"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// admissionInventory implements workloadclaims.SandboxResolver for node-CVM:
// which sandbox a calling process belongs to, and which image digests a named
// sandbox is running (docs/ratls.md, "Sandbox identity"). It is fed from the
// same CreateContainer / Synchronize events that drive enforcement — and
// pod-sandbox events for the sandbox set — so what it vouches for is exactly
// what was admitted. Caller identity comes from the kernel (SO_PEERCRED →
// cgroup → container), never from the request.
type admissionInventory struct {
	mu         sync.RWMutex
	containers map[string]ctrRec   // containerID -> record
	sandboxes  map[string]struct{} // live pod sandbox IDs
	procRoot   string
}

type ctrRec struct {
	sandboxID string
	name      string
	digest    string // canonical sha256:<hex>; "" when unresolved
}

func newAdmissionInventory(procRoot string) *admissionInventory {
	return &admissionInventory{
		containers: map[string]ctrRec{},
		sandboxes:  map[string]struct{}{},
		procRoot:   procRoot,
	}
}

// record notes an admitted container, injected sidecars included: /digests is
// an inventory of what runs in the sandbox, and the injected images are
// allowlist floor entries, so CDS drops them from workload matching itself.
func (b *admissionInventory) record(containerID, sandboxID, name, digest string) {
	if containerID == "" || sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.containers[containerID] = ctrRec{sandboxID: sandboxID, name: name, digest: digest}
	// A container implies its sandbox, so a record arriving before (or without)
	// the pod event still leaves the sandbox resolvable.
	b.sandboxes[sandboxID] = struct{}{}
}

// remove evicts a container that stopped, so its digest can't linger in a
// later pod's answer (container IDs are unique, but eviction keeps the map
// bounded and correct across pod churn).
func (b *admissionInventory) remove(containerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.containers, containerID)
}

// recordSandbox notes a live pod sandbox (RunPodSandbox / Synchronize).
func (b *admissionInventory) recordSandbox(sandboxID string) {
	if sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sandboxes[sandboxID] = struct{}{}
}

// removeSandbox evicts a removed pod sandbox and any containers still recorded
// under it, so a torn-down pod's digests cannot linger in /digests answers.
func (b *admissionInventory) removeSandbox(sandboxID string) {
	if sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sandboxes, sandboxID)
	for id, rec := range b.containers {
		if rec.sandboxID == sandboxID {
			delete(b.containers, id)
		}
	}
}

// callerForPeer resolves the calling process to its tracked container record.
// A zero PID is rejected: on node-CVM the inventory MUST bind the caller via
// kernel credentials. peer.IsAlive() is rechecked after the /proc read so a PID
// recycled between SO_PEERCRED and that read (the peer exited mid-resolution)
// is rejected rather than resolved to whatever now holds the number
// (docs/getcert-workload-binding.md, Corner 1). Callers must hold at least
// b.mu.RLock.
func (b *admissionInventory) callerForPeer(peer workloadclaims.Peer) (ctrRec, error) {
	pid := peer.PID()
	if pid <= 0 {
		return ctrRec{}, fmt.Errorf("no peer credentials on the inventory connection")
	}
	candidates, err := workloadclaims.ContainerIDCandidatesForPID(b.procRoot, pid)
	if err != nil {
		return ctrRec{}, err
	}
	// The cgroup was read by PID; confirm the pinned peer is still the process
	// that was there, so a reused PID cannot bind the caller to a victim's
	// container. Fails closed if liveness can't be confirmed — the peer exited,
	// or no pidfd was available (anomalous on a supported CC kernel).
	if !peer.IsAlive() {
		return ctrRec{}, fmt.Errorf("cannot confirm the caller is still the pinned peer process (exited during resolution, or pidfd unavailable)")
	}
	// Resolve the shallowest candidate that is a tracked container: the
	// caller's own runtime-assigned scope is always an ancestor of any cgroup
	// it could nest, so this defeats a caller that names a child cgroup with a
	// victim's container ID (see ContainerIDCandidatesForPID).
	for _, id := range candidates {
		if rec, ok := b.containers[id]; ok {
			return rec, nil
		}
	}
	return ctrRec{}, fmt.Errorf("caller cgroup names no tracked container")
}

// SandboxForPeer resolves the calling process to the pod sandbox it runs in,
// bound by kernel credentials.
func (b *admissionInventory) SandboxForPeer(peer workloadclaims.Peer) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	caller, err := b.callerForPeer(peer)
	if err != nil {
		return "", err
	}
	return caller.sandboxID, nil
}

// DigestsForSandbox returns the sorted, deduplicated image digests of every
// tracked container in the sandbox, injected containers included: this is an
// inventory of what runs there, and CDS drops the injected images itself (they
// are allowlist floor entries). An unresolved digest fails the whole answer
// rather than commit a subset as if it were the whole inventory.
func (b *admissionInventory) DigestsForSandbox(sandboxID string) ([]string, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.sandboxes[sandboxID]; !ok {
		return nil, false, nil
	}
	digests := []string{}
	for _, rec := range b.containers {
		if rec.sandboxID != sandboxID {
			continue
		}
		if rec.digest == "" {
			return nil, true, fmt.Errorf("container %q has no resolved image digest", rec.name)
		}
		digests = append(digests, rec.digest)
	}
	slices.Sort(digests)
	return slices.Compact(digests), true, nil
}
