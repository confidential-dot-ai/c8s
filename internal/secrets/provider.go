// Package secrets brokers attested secret release: it resolves the path grants
// a container holds from the allowlist and reads or writes them through a
// backing provider. Providers are dumb — no policy, no attestation, no caching;
// every authorization decision is made here, keyed on the attested container
// digest and the argv that digest was admitted with.
//
// A provider maps c8s's absolute, POSIX-shaped paths onto its own namespace
// (Vault mounts, AWS ARNs, Key Vault names). That mapping belongs to the
// provider and must be explicit; nothing here assumes the two coincide.
package secrets

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned by a provider when no secret exists at a path.
var ErrNotFound = errors.New("secrets: not found")

// ErrDenied is returned by the broker when the caller's grants do not cover a
// requested path. It is deliberately indistinguishable from ErrNotFound to a
// caller, so a denied request does not reveal whether the secret exists.
var ErrDenied = errors.New("secrets: not granted")

// Secret is one stored value. Version is the provider's own generation
// identifier, empty when the provider is unversioned.
type Secret struct {
	Path    string
	Version string
	Data    []byte
}

// Ref names one secret to read. An empty Version means the latest.
type Ref struct {
	Path    string
	Version string
}

// Provider is the adapter contract an external key-management system
// implements. There is no delete: the allowlist grants read and write only.
type Provider interface {
	// Get returns the secret at path. Version "" is the latest.
	Get(ctx context.Context, path, version string) (Secret, error)
	// GetMany returns the secrets for refs, in order. A single round trip is
	// what keeps release off a per-secret latency budget.
	GetMany(ctx context.Context, refs []Ref) ([]Secret, error)
	// Put writes data at path, creating or replacing it, and returns the
	// resulting version. Last write wins.
	Put(ctx context.Context, path string, data []byte) (Secret, error)
	// Close releases whatever leases or renewable tokens the provider holds.
	io.Closer
}

// Health is implemented by providers that can report backend reachability, so
// a serving process can fail readiness rather than accept requests it cannot
// satisfy. Providers that cannot are treated as always healthy.
type Health interface {
	Ping(ctx context.Context) error
}
