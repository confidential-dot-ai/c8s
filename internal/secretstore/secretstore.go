// Package secretstore backs the CDS secrets broker: the interface between the
// attestation-gated release endpoints and whatever holds the secrets. This PR
// ships the interface and in-memory implementations; adapters to external key
// managers (openbao, vault, AWS KMS) implement Store in their own PRs.
//
// Secrets are scoped by Ref{Entry, Path}: the workload entry (an allowlist
// workload whose container set a pod attested) plus the policy path granted to
// that entry. Entry scoping lets two tenants share a mount path with different
// values, provided their workload sets differ — see docs/secrets-broker.md.
package secretstore

import (
	"context"
	"errors"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ErrNotFound is returned by Get when no secret exists at the ref.
var ErrNotFound = errors.New("secretstore: not found")

// Ref identifies a secret: the workload entry it belongs to and its policy path.
type Ref struct {
	Entry string
	Path  string
}

// Store is the broker's backend. Get receives the requesting container digest
// so per-caller backends (leased credentials) are expressible; single-value
// implementations ignore it. The zero digest means "no workload requester"
// (operator paths).
type Store interface {
	Get(ctx context.Context, ref Ref, requester types.Digest) ([]byte, error)
	Set(ctx context.Context, ref Ref, value []byte) error
	Delete(ctx context.Context, ref Ref) error
}

// MemStore is an in-memory Store: one value per ref, last write wins. It loses
// everything on CDS restart — that is the intended direct-mode posture
// (re-deposit after a total CDS loss, docs/secrets-broker.md), never a PV of
// plaintext.
type MemStore struct {
	mu      sync.RWMutex
	secrets map[Ref][]byte
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{secrets: make(map[Ref][]byte)}
}

// Get returns a copy of the stored value, or ErrNotFound.
func (m *MemStore) Get(_ context.Context, ref Ref, _ types.Digest) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.secrets[ref]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

// Set stores a copy of value at ref, replacing any previous value.
func (m *MemStore) Set(_ context.Context, ref Ref, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[ref] = append([]byte(nil), value...)
	return nil
}

// Delete removes ref. Deleting an absent ref is not an error.
func (m *MemStore) Delete(_ context.Context, ref Ref) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, ref)
	return nil
}

// Len reports how many refs hold a value. Test and metrics helper.
func (m *MemStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.secrets)
}
