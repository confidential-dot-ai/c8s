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

// Origin records what put a value at a path.
type Origin string

const (
	// OriginWorkload marks a value CDS generated for a workload that found its
	// path empty.
	OriginWorkload Origin = "workload"
	// OriginOperator marks a value an operator supplied over PUT /secrets/*.
	OriginOperator Origin = "operator"
)

// Held describes what a path already contained when a write arrived. It carries
// the origin and never the value: the operator write path reports what it is
// about to displace, and that report must not turn a write into a read.
type Held struct {
	Exists bool
	Origin Origin
}

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
	// path holds afterwards and what was already there. held.Exists reports that
	// the write did not happen.
	PutIfAbsent(ctx context.Context, path string, value []byte, by Origin) (current []byte, held Held, err error)
	// Put stores value at path, replacing anything already there, and reports
	// what it displaced.
	Put(ctx context.Context, path string, value []byte, by Origin) (Held, error)
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
	values   map[string]entry
	maxPaths int
	maxValue int
}

type entry struct {
	value  []byte
	origin Origin
}

// NewMemoryStore builds the store. maxPaths bounds distinct paths; maxValue
// bounds one value.
func NewMemoryStore(maxPaths, maxValue int) *MemoryStore {
	return &MemoryStore{
		values:   make(map[string]entry),
		maxPaths: maxPaths,
		maxValue: maxValue,
	}
}

func (s *MemoryStore) Get(_ context.Context, path string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.values[path]
	if !ok {
		return nil, ErrNotFound
	}
	// Copy: the caller must not be able to mutate stored state through the
	// slice it is handed.
	return append([]byte(nil), e.value...), nil
}

func (s *MemoryStore) PutIfAbsent(_ context.Context, path string, value []byte, by Origin) ([]byte, Held, error) {
	if err := s.checkValue(value); err != nil {
		return nil, Held{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.values[path]; ok {
		return append([]byte(nil), e.value...), Held{Exists: true, Origin: e.origin}, nil
	}
	if err := s.checkRoom(); err != nil {
		return nil, Held{}, err
	}
	s.values[path] = entry{value: append([]byte(nil), value...), origin: by}
	return append([]byte(nil), value...), Held{}, nil
}

func (s *MemoryStore) Put(_ context.Context, path string, value []byte, by Origin) (Held, error) {
	if err := s.checkValue(value); err != nil {
		return Held{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, existed := s.values[path]
	if !existed {
		if err := s.checkRoom(); err != nil {
			return Held{}, err
		}
	}
	s.values[path] = entry{value: append([]byte(nil), value...), origin: by}
	return Held{Exists: existed, Origin: prior.origin}, nil
}

func (s *MemoryStore) checkValue(value []byte) error {
	if len(value) > s.maxValue {
		return fmt.Errorf("secrets: value is %d bytes, limit is %d", len(value), s.maxValue)
	}
	return nil
}

// checkRoom guards the path bound. Callers hold the lock and have established
// the path is absent, so this is only ever asked about a write that grows the
// map.
func (s *MemoryStore) checkRoom() error {
	if len(s.values) >= s.maxPaths {
		return fmt.Errorf("secrets: store holds %d paths, limit is %d", len(s.values), s.maxPaths)
	}
	return nil
}

// Len reports how many paths the store holds, for metrics and tests.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}
