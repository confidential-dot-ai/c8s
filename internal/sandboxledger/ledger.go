// Package sandboxledger records which node's admission inventory vouched for a
// pod sandbox, so a later decision about that sandbox asks the same inventory
// rather than one the requester names.
//
// A sandbox token carries the host that signed it, and CDS reads that host to
// find the key that verifies the signature. That is sound for issuance — a wrong
// host simply yields a key the signature fails under — but it makes the
// requester the one choosing which inventory is asked. Anything able to answer
// on the inventory port inside the operator's node CIDRs could otherwise sign a
// token for someone else's sandbox ID, be believed about what that sandbox runs,
// and have the answer used to release that sandbox's secrets.
//
// The binding is therefore taken once, at issuance, and is first-write-wins:
// the first inventory to be believed about a sandbox is the only one believed
// about it. See docs/secrets.md.
package sandboxledger

import (
	"fmt"
	"sync"
	"time"
)

const (
	// MaxSnapshotEntries bounds handoff memory independently of a deployment's
	// configured live-entry limit.
	MaxSnapshotEntries    = 10000
	maxSandboxIDBytes     = 128
	maxInventoryHostBytes = 255
)

// Snapshot is the bounded sandbox-to-inventory state for CDS handoff.
type Snapshot struct {
	Entries []SnapshotEntry `json:"entries,omitempty"`
}

// SnapshotEntry is one live first-write-wins sandbox binding.
type SnapshotEntry struct {
	SandboxID     string    `json:"sandbox_id"`
	InventoryHost string    `json:"inventory_host"`
	Expires       time.Time `json:"expires"`
}

// binding is what the ledger holds for one sandbox: the node address whose
// inventory vouched for it, and when that stops being believed.
type binding struct {
	host    string
	expires time.Time
}

// Ledger maps a sandbox ID to the inventory that vouched for it.
//
// Entries expire so a ledger cannot outlive the certificates it describes, and
// the total is capped so sandbox churn — or an inventory minting tokens for
// fabricated IDs — cannot grow it without bound. CDS is a single in-memory
// process whose OOM costs the cluster its mesh CA, so an unbounded map here
// would be a denial primitive.
type Ledger struct {
	mu       sync.Mutex
	bindings map[string]binding
	ttl      time.Duration
	max      int
	now      func() time.Time
	frozen   bool
}

// New builds a ledger. ttl should be the maximum leaf lifetime: a binding is
// only useful while a certificate carrying that sandbox ID could still be
// presented.
func New(ttl time.Duration, max int) *Ledger {
	return &Ledger{
		bindings: make(map[string]binding),
		ttl:      ttl,
		max:      max,
		now:      time.Now,
	}
}

// Record binds sandboxID to inventoryHost, reporting whether the binding holds.
//
// It returns false only when a *different*, unexpired host already owns the
// sandbox. The same host re-recording is a refresh, not a conflict: a workload
// renews its certificate on an interval and re-presents the same pair, so
// once-only would refuse a pod its own renewal.
//
// A caller must not deny issuance on false. get-cert has no token-less retry, so
// refusing there would let one pre-claim wedge a pod for a full certificate
// lifetime — a worse outcome than the theft it prevents. False means the sandbox
// is unsafe to answer questions about, not that the requester is unauthorized.
func (l *Ledger) Record(sandboxID, inventoryHost string) bool {
	if sandboxID == "" || inventoryHost == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.frozen {
		return false
	}

	now := l.now()
	if b, ok := l.bindings[sandboxID]; ok && now.Before(b.expires) {
		if b.host != inventoryHost {
			return false
		}
	}
	if _, ok := l.bindings[sandboxID]; !ok && len(l.bindings) >= l.max {
		l.evictExpiredLocked(now)
		if len(l.bindings) >= l.max {
			return false
		}
	}
	l.bindings[sandboxID] = binding{host: inventoryHost, expires: now.Add(l.ttl)}
	return true
}

// Lookup returns the inventory host bound to sandboxID. An expired or absent
// binding reports false, which callers must treat as fail-closed: without it
// there is no inventory this process is willing to believe about the sandbox.
func (l *Ledger) Lookup(sandboxID string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.bindings[sandboxID]
	if !ok || !l.now().Before(b.expires) {
		return "", false
	}
	return b.host, true
}

// Len reports the number of live bindings, for metrics and tests.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictExpiredLocked(l.now())
	return len(l.bindings)
}

// Snapshot returns every live binding without extending its expiry.
func (l *Ledger) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.evictExpiredLocked(now)
	out := Snapshot{Entries: make([]SnapshotEntry, 0, len(l.bindings))}
	for sandboxID, item := range l.bindings {
		out.Entries = append(out.Entries, SnapshotEntry{SandboxID: sandboxID, InventoryHost: item.host, Expires: item.expires})
	}
	return out
}

// Freeze stops new bindings and returns one atomic snapshot.
func (l *Ledger) Freeze() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.frozen = true
	now := l.now()
	l.evictExpiredLocked(now)
	out := Snapshot{Entries: make([]SnapshotEntry, 0, len(l.bindings))}
	for sandboxID, item := range l.bindings {
		out.Entries = append(out.Entries, SnapshotEntry{SandboxID: sandboxID, InventoryHost: item.host, Expires: item.expires})
	}
	return out
}

// Resume allows new bindings after an aborted pre-activation handoff.
func (l *Ledger) Resume() {
	l.mu.Lock()
	l.frozen = false
	l.mu.Unlock()
}

// RestoreSnapshot atomically restores live bindings with the same expiry and
// first-write-wins meaning. It rejects malformed or oversized input.
func (l *Ledger) RestoreSnapshot(snapshot Snapshot) error {
	if err := ValidateSnapshot(snapshot, l.max); err != nil {
		return err
	}
	now := l.now()
	next := make(map[string]binding, len(snapshot.Entries))
	for _, item := range snapshot.Entries {
		if now.Before(item.Expires) {
			next[item.SandboxID] = binding{host: item.InventoryHost, expires: item.Expires}
		}
	}
	l.mu.Lock()
	l.bindings = next
	l.mu.Unlock()
	return nil
}

// ValidateSnapshot checks structural and size limits without exposing values.
func ValidateSnapshot(snapshot Snapshot, max int) error {
	if max <= 0 || max > MaxSnapshotEntries || len(snapshot.Entries) > max {
		return fmt.Errorf("sandbox ledger snapshot has %d entries, limit is %d", len(snapshot.Entries), max)
	}
	seen := make(map[string]struct{}, len(snapshot.Entries))
	for _, item := range snapshot.Entries {
		if item.SandboxID == "" || len(item.SandboxID) > maxSandboxIDBytes || item.InventoryHost == "" || len(item.InventoryHost) > maxInventoryHostBytes || item.Expires.IsZero() {
			return fmt.Errorf("sandbox ledger snapshot contains an invalid entry")
		}
		if _, exists := seen[item.SandboxID]; exists {
			return fmt.Errorf("sandbox ledger snapshot contains a duplicate sandbox")
		}
		seen[item.SandboxID] = struct{}{}
	}
	return nil
}

func (l *Ledger) evictExpiredLocked(now time.Time) {
	for id, b := range l.bindings {
		if !now.Before(b.expires) {
			delete(l.bindings, id)
		}
	}
}

// EvictionLoop drops expired bindings on each tick until done is closed.
func (l *Ledger) EvictionLoop(done <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			l.mu.Lock()
			l.evictExpiredLocked(l.now())
			l.mu.Unlock()
		}
	}
}
