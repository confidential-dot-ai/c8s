package nriimagepolicy

import (
	"slices"
	"sync"
)

// liveInstances tracks the containers currently running on this node and the
// rule each was admitted under, so an outstanding update can say which of them
// the target policy no longer admits. A nil *liveInstances is inert on the
// admission path, so a plugin assembled without one still runs.
//
// It is separate from admissionInventory on purpose. The inventory is optional
// (it exists only with workload_claims.socket_dir) and its per-sandbox history
// is cumulative by design — it answers "what ever ran here". Drain accounting
// needs the opposite: the live set, emptied as containers go away, available
// whenever a CDS pull is configured.
type liveInstances struct {
	mu      sync.Mutex
	live    map[string]instance
	pending map[string]struct{}
	// removed is the rule set the outstanding update drops, kept so a
	// container admitted after the acknowledgement — the source policy still
	// admits it until the switch — joins the pending set rather than becoming
	// a violation the moment the target applies.
	removed map[string]struct{}
	// onDrained fires when the last pending instance is gone. Called without
	// the lock held; nil until the state loop installs it.
	onDrained func()
}

// instance is one live container: the sandbox it belongs to and the key of the
// allowlist rule that admitted it. An empty rule key means the container was
// admitted by something other than a CDS rule — always_allow, an exempt
// namespace, or audit mode — so no policy update can remove its permission.
type instance struct {
	sandboxID string
	ruleKey   string
}

func newLiveInstances() *liveInstances {
	return &liveInstances{
		live:    map[string]instance{},
		pending: map[string]struct{}{},
		removed: map[string]struct{}{},
	}
}

// setOnDrained installs the callback fired when the last pending instance is
// removed.
func (l *liveInstances) setOnDrained(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onDrained = fn
}

// admit records a container the plugin let run. Re-admitting a container ID
// (a restarted check of the same instance) keeps its pending mark: what makes
// an instance pending is the rule it started under, not the current policy.
// A container admitted under a rule the outstanding update drops becomes
// pending at once — the source policy still admits it, and after the switch it
// must drain rather than count as a violation.
func (l *liveInstances) admit(containerID, sandboxID, ruleKey string) {
	if l == nil || containerID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.live[containerID] = instance{sandboxID: sandboxID, ruleKey: ruleKey}
	if ruleKey == "" {
		return
	}
	if _, dropped := l.removed[ruleKey]; dropped {
		l.pending[containerID] = struct{}{}
	}
}

// remove forgets a stopped container and fires onDrained when it was the last
// pending one.
func (l *liveInstances) remove(containerID string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.live, containerID)
	_, wasPending := l.pending[containerID]
	delete(l.pending, containerID)
	drained := wasPending && len(l.pending) == 0
	fn := l.onDrained
	l.mu.Unlock()

	if drained && fn != nil {
		fn()
	}
}

// removeSandbox forgets every container of a torn-down pod sandbox. NRI
// normally reports each container's removal first; this closes the case where
// it does not, which would otherwise leave an update pending forever.
func (l *liveInstances) removeSandbox(sandboxID string) {
	if l == nil || sandboxID == "" {
		return
	}
	l.mu.Lock()
	hadPending := len(l.pending) > 0
	for id, inst := range l.live {
		if inst.sandboxID != sandboxID {
			continue
		}
		delete(l.live, id)
		delete(l.pending, id)
	}
	drained := hadPending && len(l.pending) == 0
	fn := l.onDrained
	l.mu.Unlock()

	if drained && fn != nil {
		fn()
	}
}

// markPending takes the set an acknowledgement covers: every live instance
// admitted under one of the removed rules, by sorted container ID. It replaces
// any earlier pending set — v1 runs one update at a time, so a new one
// supersedes — and remembers the rule set, which is what keeps a container
// created before the switch out of the violation path.
func (l *liveInstances) markPending(removed map[string]struct{}) []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.pending = map[string]struct{}{}
	l.removed = removed
	ids := make([]string, 0, len(l.live))
	for id, inst := range l.live {
		if inst.ruleKey == "" {
			continue
		}
		if _, ok := removed[inst.ruleKey]; !ok {
			continue
		}
		l.pending[id] = struct{}{}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// isPending reports whether a container holds a permission the active policy
// no longer grants. Such a container is authorized until it stops.
func (l *liveInstances) isPending(containerID string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.pending[containerID]
	return ok
}

// pendingCount reports how many instances are still to drain.
func (l *liveInstances) pendingCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending)
}

// clearPending drops the pending set, which is what a completed update leaves
// behind.
func (l *liveInstances) clearPending() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = map[string]struct{}{}
	l.removed = map[string]struct{}{}
}
