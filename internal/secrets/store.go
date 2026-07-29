// Package secrets holds the CDS secret store and the policy that gates access
// to it. See docs/secrets.md.
package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// ErrNotFound reports a path the store does not hold.
var ErrNotFound = errors.New("secrets: no such path")

// Store is the secret backend.
//
// Generation lives above the store, not inside it: a backing store generates in
// its own way — a KMS wraps a key, a vault mints its own — so a store that also
// chose values would force every backend to reimplement or contradict this
// one's policy. PutIfAbsent is a compare-and-set, which every real key-value
// store offers.
type Store interface {
	Get(ctx context.Context, path string) ([]byte, error)
	// PutIfAbsent stores value at path if nothing is there, returning what the
	// path holds afterwards and whether this call is what put it there.
	PutIfAbsent(ctx context.Context, path string, value []byte) (current []byte, created bool, err error)
}

// GeneratedValueBytes is the size of a value CDS mints for a workload that
// finds its path empty. 32 bytes is a symmetric key's worth of entropy, which
// is what these values are used as.
const GeneratedValueBytes = 32

// Generate returns a fresh secret value.
func Generate() ([]byte, error) {
	b := make([]byte, GeneratedValueBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("secrets: generate value: %w", err)
	}
	return b, nil
}

// MemoryStore keeps secrets in the CDS process and nowhere else. They do not
// survive a restart — see docs/secrets.md, "Restarts".
//
// Both bounds are fail-closed. CDS is a single in-memory process holding the
// mesh CA, so a workload able to grow this map without limit could OOM it and
// take every certificate in the cluster with it.
type MemoryStore struct {
	mu       sync.RWMutex
	values   map[string][]byte
	maxPaths int
	maxValue int
}

// NewMemoryStore builds the store. maxPaths bounds distinct paths; maxValue
// bounds one value.
func NewMemoryStore(maxPaths, maxValue int) *MemoryStore {
	return &MemoryStore{
		values:   make(map[string][]byte),
		maxPaths: maxPaths,
		maxValue: maxValue,
	}
}

func (s *MemoryStore) Get(_ context.Context, path string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.values[path]
	if !ok {
		return nil, ErrNotFound
	}
	// Copy: the caller must not be able to mutate stored state through the
	// slice it is handed.
	return append([]byte(nil), v...), nil
}

func (s *MemoryStore) PutIfAbsent(_ context.Context, path string, value []byte) ([]byte, bool, error) {
	if len(value) > s.maxValue {
		return nil, false, fmt.Errorf("secrets: value is %d bytes, limit is %d", len(value), s.maxValue)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.values[path]; ok {
		return append([]byte(nil), v...), false, nil
	}
	if len(s.values) >= s.maxPaths {
		return nil, false, fmt.Errorf("secrets: store holds %d paths, limit is %d", len(s.values), s.maxPaths)
	}
	s.values[path] = append([]byte(nil), value...)
	return append([]byte(nil), value...), true, nil
}

// Len reports how many paths the store holds, for metrics and tests.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}
