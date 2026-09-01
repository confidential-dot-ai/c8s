package nriimagepolicy

import (
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	"github.com/containerd/nri/pkg/api"
)

// admissionInventory implements workloadclaims.SandboxResolver for node-CVM:
// which sandbox a calling process belongs to, and which image digests a named
// sandbox is running (docs/ratls.md, "Sandbox identity"). It is fed from the
// same CreateContainer / Synchronize events that drive enforcement — and
// pod-sandbox events for the sandbox set. Caller identity comes from the kernel
// (SO_PEERCRED → cgroup → container), never from the request.
//
// "Admitted" here and in every caller means the plugin let the container run,
// not that it passed the checks: audit mode or an undeliverable kill each
// leave one running, and the inventory reports what runs.
type admissionInventory struct {
	mu         sync.RWMutex
	containers map[string]ctrRec   // live containerID -> record (caller resolution)
	admitted   map[string]sbxRec   // sandboxID -> everything ever admitted there
	sandboxes  map[string]struct{} // live pod sandbox IDs
	pods       map[string]podRec   // live sandbox ID -> Kubernetes identity
	procRoot   string
	policy     *policyStore
	generation uint64
}

type ctrRec struct {
	sandboxID      string
	name           string // unread
	digest         string // canonical sha256:<hex>; "" when unresolved
	argv           []string
	bindMounts     []string
	bindMountKinds map[string]string
	envNames       []string
	mountsObserved bool
	envObserved    bool
}

type podRec struct {
	name      string
	namespace string
	uid       string
}

// sbxRec is a sandbox's admission high-water mark: every distinct (digest,
// argv) admitted in it, keyed for dedup, never pruned while the sandbox lives.
// See docs/secrets.md — "The report is a high-water mark".
type sbxRec struct {
	byKey      map[string]workloadclaims.SandboxContainer
	unresolved map[string]struct{} // container IDs with no digest; cleared only by a later resolved record for the same ID
}

func newAdmissionInventory(procRoot string, policies ...*policyStore) *admissionInventory {
	b := &admissionInventory{
		containers: map[string]ctrRec{},
		admitted:   map[string]sbxRec{},
		sandboxes:  map[string]struct{}{},
		pods:       map[string]podRec{},
		procRoot:   procRoot,
	}
	if len(policies) == 1 {
		b.policy = policies[0]
	}
	return b
}

// record notes an admitted container, including c8s helpers. /digests is an
// inventory of the complete admitted set. CDS keeps every record when it
// resolves an exact named workload.
// argv is the effective OCI process.args the container runs.
func (b *admissionInventory) record(containerID, sandboxID, name, digest string, argv []string, observed ...containerObservation) {
	if containerID == "" || sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record := ctrRec{sandboxID: sandboxID, name: name, digest: digest, argv: slices.Clone(argv)}
	if len(observed) == 1 {
		record.bindMounts = slices.Clone(observed[0].bindMounts)
		record.bindMountKinds = cloneStringMap(observed[0].bindMountKinds)
		record.envNames = slices.Clone(observed[0].envNames)
		record.mountsObserved = true
		record.envObserved = true
	}
	b.containers[containerID] = record
	b.generation++

	rec, ok := b.admitted[sandboxID]
	if !ok {
		rec = sbxRec{
			byKey:      map[string]workloadclaims.SandboxContainer{},
			unresolved: map[string]struct{}{},
		}
	}
	if digest == "" {
		rec.unresolved[containerID] = struct{}{}
	} else {
		delete(rec.unresolved, containerID)
		c := workloadclaims.SandboxContainer{Name: name, Digest: digest, Argv: slices.Clone(argv)}
		if len(observed) == 1 {
			c.BindMounts = slices.Clone(observed[0].bindMounts)
			c.BindMountKinds = cloneStringMap(observed[0].bindMountKinds)
			c.EnvNames = slices.Clone(observed[0].envNames)
			c.MountsObserved = true
			c.EnvObserved = true
		}
		rec.byKey[c.Key()] = c
	}
	b.admitted[sandboxID] = rec

	// A container implies its sandbox, so a record arriving before (or without)
	// the pod event still leaves the sandbox resolvable.
	b.sandboxes[sandboxID] = struct{}{}
}

// remove evicts a stopped container from caller resolution only. The sandbox's
// admission record keeps it: a stopped container must not bind a caller, but it
// still ran here (sbxRec). That includes an unresolved digest, so a container
// that stops before one resolves closes its sandbox's answer for the sandbox's
// life.
func (b *admissionInventory) remove(containerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.containers[containerID]; ok {
		delete(b.containers, containerID)
		b.generation++
	}
}

// recordSandbox notes a live pod sandbox (RunPodSandbox / Synchronize).
func (b *admissionInventory) recordSandbox(sandboxID string) {
	if sandboxID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sandboxes[sandboxID] = struct{}{}
	b.generation++
}

// recordPod records the stable Kubernetes identity that containerd supplied
// with a live sandbox. The control plane can choose these names, so evidence
// reports them as observations. It does not treat them as trust anchors.
func (b *admissionInventory) recordPod(pod *api.PodSandbox) {
	if pod == nil || pod.GetId() == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sandboxes[pod.GetId()] = struct{}{}
	b.pods[pod.GetId()] = podRec{name: pod.GetName(), namespace: pod.GetNamespace(), uid: pod.GetUid()}
	b.generation++
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
	delete(b.pods, sandboxID)
	delete(b.admitted, sandboxID)
	for id, rec := range b.containers {
		if rec.sandboxID == sandboxID {
			delete(b.containers, id)
		}
	}
	b.generation++
}

// RuntimeInventory returns the live node-wide inventory. It uses current
// containers, not the per-sandbox high-water marks used for secret release.
// One unresolved live digest fails the whole snapshot.
func (b *admissionInventory) RuntimeInventory() (workloadclaims.RuntimeInventory, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := workloadclaims.RuntimeInventory{Schema: workloadclaims.RuntimeInventorySchema, Generation: b.generation}
	if b.policy != nil {
		if snap := b.policy.current(); snap != nil {
			out.PolicySHA256 = snap.digest
			out.PolicyVersion = snap.version
		}
	}
	for id, rec := range b.containers {
		if rec.digest == "" {
			return workloadclaims.RuntimeInventory{}, fmt.Errorf("live container %s has no resolved image digest", id)
		}
		pod := b.pods[rec.sandboxID]
		out.Containers = append(out.Containers, workloadclaims.RuntimeContainer{
			Namespace:      pod.namespace,
			PodName:        pod.name,
			PodUID:         pod.uid,
			SandboxID:      rec.sandboxID,
			ContainerName:  rec.name,
			ContainerID:    id,
			Digest:         rec.digest,
			Argv:           slices.Clone(rec.argv),
			BindMounts:     slices.Clone(rec.bindMounts),
			BindMountKinds: cloneStringMap(rec.bindMountKinds),
			EnvNames:       slices.Clone(rec.envNames),
			MountsObserved: rec.mountsObserved,
			EnvObserved:    rec.envObserved,
		})
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Key() < out.Containers[j].Key() })
	return out, nil
}

// admitsLiveRuntime checks the generation barrier for an authenticated policy
// swap. Each live container must pass admission, and each live Pod must resolve
// to one exact named workload. A digest-only entry is not enough to leave the
// cold-boot state. This prevents the active policy from retaining the same
// arbitrary-command property as the local bootstrap floor.
func (b *admissionInventory) admitsLiveRuntime(policy *allowlist.Allowlist, index *allowlist.Index) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	bySandbox := make(map[string][]allowlist.RunningContainer)
	for id, rec := range b.containers {
		if rec.digest == "" {
			return fmt.Errorf("live container %s has no resolved image digest", id)
		}
		running := allowlist.RunningContainer{
			Digest:         rec.digest,
			Argv:           slices.Clone(rec.argv),
			BindMounts:     slices.Clone(rec.bindMounts),
			BindMountKinds: cloneStringMap(rec.bindMountKinds),
			EnvNames:       slices.Clone(rec.envNames),
			MountsObserved: rec.mountsObserved,
			EnvObserved:    rec.envObserved,
		}
		if !index.AdmitsContainer(running) {
			return fmt.Errorf("live container %s (%s) is not admitted", id, rec.digest)
		}
		bySandbox[rec.sandboxID] = append(bySandbox[rec.sandboxID], running)
	}
	for sandboxID, running := range bySandbox {
		if _, _, err := policy.MatchWorkload(running); err != nil {
			pod := b.pods[sandboxID]
			return fmt.Errorf("live pod %s/%s (%s) has no unique exact workload identity: %w", pod.namespace, pod.name, sandboxID, err)
		}
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
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

// DigestsForSandbox reports every container ever admitted in the sandbox,
// including c8s helper containers. CDS matches the complete set against one
// exact named workload. Digests is the sorted, deduplicated digest set
// (issuance); containers carries the
// per-container (digest, argv) detail, sorted for a stable answer.
//
// An unresolved digest fails the whole answer rather than commit a subset as if
// it were the whole inventory.
func (b *admissionInventory) DigestsForSandbox(sandboxID string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.sandboxes[sandboxID]; !ok {
		return nil, nil, false, nil
	}
	rec := b.admitted[sandboxID]
	if len(rec.unresolved) > 0 {
		return nil, nil, true, fmt.Errorf("sandbox %s admitted a container with no resolved image digest", sandboxID)
	}
	digests := []string{}
	containers := make([]workloadclaims.SandboxContainer, 0, len(rec.byKey))
	for _, c := range rec.byKey {
		digests = append(digests, c.Digest)
		containers = append(containers, c)
	}
	slices.Sort(digests)
	slices.SortFunc(containers, workloadclaims.SandboxContainer.Compare)
	return slices.Compact(digests), containers, true, nil
}
