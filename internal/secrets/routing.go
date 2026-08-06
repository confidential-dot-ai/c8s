package secrets

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// ErrExternal refuses a write to a path backed by the external KMS. Writes do
// not reach the vault, so the value lives where the operator put it; the
// handlers map this to a 409 naming OriginExternal, never to a fetch.
var ErrExternal = errors.New("secrets: path is backed by the external KMS")

// errNotConfigured fails closed a mapped path whose credential has not been
// re-applied since a restart. The mappings are persisted; the credential is
// not, and a mapped path must never fall through to minting.
var errNotConfigured = errors.New("secrets: external KMS credential not applied since restart")

// OriginExternal marks a path whose value lives in the external KMS. It never
// appears as Held.Origin from a successful write: writes to such paths are
// refused with ErrExternal instead.
const OriginExternal Origin = "external"

// RoutingStore dispatches between the external KMS backend (mapped paths) and
// the memory store (everything else). A mapping shadows any memory value at
// the same path; removing the mapping lets it resurface. It uses the network
// backend conventions on Store.
type RoutingStore struct {
	Mem      *MemoryStore
	External *ExternalBackend
}

func (s *RoutingStore) Get(ctx context.Context, path string) ([]byte, error) {
	if s.External.Mapped(path) {
		return s.External.Fetch(ctx, path)
	}
	return s.Mem.Get(ctx, path)
}

func (s *RoutingStore) PutIfAbsent(ctx context.Context, path string, value []byte, by Origin) ([]byte, Held, error) {
	if s.External.Mapped(path) {
		return nil, Held{}, ErrExternal
	}
	return s.Mem.PutIfAbsent(ctx, path, value, by)
}

func (s *RoutingStore) Put(ctx context.Context, path string, value []byte, by Origin) (Held, error) {
	if s.External.Mapped(path) {
		return Held{}, ErrExternal
	}
	return s.Mem.Put(ctx, path, value, by)
}

// ExternalStatus is what GET on the config route reports: the mapping set,
// whether a credential is live, the last fetch per path, and any mapped path
// currently shadowing a memory value. It never carries the credential or a
// fetched value.
type ExternalStatus struct {
	Configured bool                    `json:"configured"`
	Mappings   map[string]AzureMapping `json:"mappings"`
	LastFetch  map[string]FetchRecord  `json:"lastFetch,omitempty"`
	Shadowed   []string                `json:"shadowed,omitempty"`
}

// ExternalBackend holds the mapping set and the live credential config. The
// two are updated together under mu; fetches look up under a read lock and
// then release it before any network I/O, so an apply never waits on the KMS
// and a fetch never blocks an apply.
type ExternalBackend struct {
	mu       sync.RWMutex
	mapped   map[string]AzureMapping // persisted set; == live.mappings when live != nil
	live     *azureConfig
	persist  func(map[string]AzureMapping) error // nil disables persistence (tests)
	maxValue int
	// newConfig builds the live config on Apply; nil means newAzureConfig.
	// Tests point it at a stubbed KMS.
	newConfig func(AzureCredential, map[string]AzureMapping) *azureConfig
}

// NewExternalBackend loads the persisted mapping set (nil mappings means none)
// and returns a backend with no live credential.
func NewExternalBackend(persisted map[string]AzureMapping, persist func(map[string]AzureMapping) error, maxValue int) *ExternalBackend {
	if persisted == nil {
		persisted = map[string]AzureMapping{}
	}
	return &ExternalBackend{mapped: persisted, persist: persist, maxValue: maxValue}
}

// Mapped reports whether path is backed by the vault, regardless of whether a
// credential is live.
func (b *ExternalBackend) Mapped(path string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.mapped[path]
	return ok
}

// Fetch returns the vault value for a mapped path, failing closed when no
// credential has been applied since startup. The mapping lookup and the live
// read share one critical section, so Fetch is safe regardless of what the
// caller checked first.
func (b *ExternalBackend) Fetch(ctx context.Context, path string) ([]byte, error) {
	b.mu.RLock()
	live := b.live
	_, mapped := b.mapped[path]
	b.mu.RUnlock()
	if !mapped {
		return nil, fmt.Errorf("secrets: %s is not azure-backed", path)
	}
	if live == nil {
		return nil, errNotConfigured
	}
	value, err := live.fetch(ctx, path)
	if err == nil && b.maxValue > 0 && len(value) > b.maxValue {
		return nil, fmt.Errorf("secrets: vault value is %d bytes, limit is %d", len(value), b.maxValue)
	}
	return value, err
}

// Apply replaces the whole backend state: validate (done by the caller),
// persist, then swap. The lock spans persist and swap so two concurrent
// applies cannot interleave into a live set that diverges from what a restart
// would reload; a persist failure refuses the apply outright.
func (b *ExternalBackend) Apply(cred AzureCredential, mappings map[string]AzureMapping) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.persist != nil {
		if err := b.persist(mappings); err != nil {
			return fmt.Errorf("secrets: persist azure mappings: %w", err)
		}
	}
	newConfig := b.newConfig
	if newConfig == nil {
		newConfig = newAzureConfig
	}
	b.mapped = mappings
	b.live = newConfig(cred, mappings)
	return nil
}

// Clear removes all mappings and the credential.
func (b *ExternalBackend) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.persist != nil {
		if err := b.persist(map[string]AzureMapping{}); err != nil {
			return fmt.Errorf("secrets: persist azure mappings: %w", err)
		}
	}
	b.mapped = map[string]AzureMapping{}
	b.live = nil
	return nil
}

// Status snapshots the backend for the operator. shadowed lists mapped paths
// that currently cover a memory value, so unmapping is never a surprise.
func (b *ExternalBackend) Status(mem *MemoryStore) ExternalStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	st := ExternalStatus{
		Configured: b.live != nil,
		Mappings:   make(map[string]AzureMapping, len(b.mapped)),
	}
	for p, m := range b.mapped {
		st.Mappings[p] = m
	}
	if b.live != nil {
		b.live.mu.Lock()
		st.LastFetch = make(map[string]FetchRecord, len(b.live.last))
		for p, r := range b.live.last {
			st.LastFetch[p] = r
		}
		b.live.mu.Unlock()
	}
	for p := range b.mapped {
		if _, err := mem.Get(context.Background(), p); err == nil {
			st.Shadowed = append(st.Shadowed, p)
		}
	}
	slices.Sort(st.Shadowed)
	return st
}
