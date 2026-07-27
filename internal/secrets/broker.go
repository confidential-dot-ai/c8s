package secrets

import (
	"context"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Subject is who a release is authorized for: the image digest a container was
// admitted as, and the effective argv it was admitted with.
//
// INVARIANT: both fields come from the component that made the admission
// decision — nri-image-policy's CreateContainer record on node-CVM, the guest
// monitor's bundle read under kata — and NEVER from the request being served.
// The broker cannot verify them and does not try. A caller that fills a Subject
// from its own request body has authorized nothing: it has let the requester
// name its own entitlement.
type Subject struct {
	Digest types.Digest
	Argv   []string
}

// Broker resolves a Subject's grants and moves secrets through a Provider.
//
// Index.PathGrants attributes a grant only to an entry whose argv policy the
// subject's argv matched, so a digest shared with a permissive entry cannot
// borrow a strict entry's paths. Floor digests hold no grants, which is what
// keeps every c8s-injected component unentitled.
type Broker struct {
	Provider Provider
	// Index returns the allowlist projection to resolve against. It is a
	// function because the served allowlist is swapped on every operator write.
	Index func() (*allowlist.Index, error)
}

// Grants returns the read and write paths subj holds.
func (b *Broker) Grants(subj Subject) (allowlist.PathPolicy, error) {
	idx, err := b.Index()
	if err != nil {
		return allowlist.PathPolicy{}, fmt.Errorf("load allowlist: %w", err)
	}
	return idx.PathGrants(subj.Digest.String(), subj.Argv), nil
}

// Fetch returns the secrets at refs. Every ref must satisfy a read grant subj
// holds; one denial fails the whole call, so a partial result is never mistaken
// for a complete one.
//
// refs must be non-empty: a grant may name a subtree, which no provider can be
// asked to enumerate cheaply or consistently, so a caller always names the exact
// paths it wants.
func (b *Broker) Fetch(ctx context.Context, subj Subject, refs []Ref) ([]Secret, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("secrets: fetch requires at least one path")
	}
	idx, err := b.Index()
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}
	for _, r := range refs {
		if !idx.AdmitsRead(subj.Digest.String(), subj.Argv, r.Path) {
			return nil, ErrDenied
		}
	}
	out, err := b.Provider.GetMany(ctx, refs)
	if err != nil {
		return nil, err
	}
	// Only the requested paths were authorized, so a provider answering with any
	// other path — or with a short list — must fail the call rather than hand
	// back material nothing granted.
	if len(out) != len(refs) {
		return nil, fmt.Errorf("secrets: provider returned %d of %d requested secrets", len(out), len(refs))
	}
	for i, s := range out {
		if s.Path != refs[i].Path {
			return nil, fmt.Errorf("secrets: provider returned %q for requested path %q", s.Path, refs[i].Path)
		}
	}
	return out, nil
}

// Put writes data at path, which must satisfy a write grant subj holds. A write
// grant implies create and update.
func (b *Broker) Put(ctx context.Context, subj Subject, path string, data []byte) (Secret, error) {
	idx, err := b.Index()
	if err != nil {
		return Secret{}, fmt.Errorf("load allowlist: %w", err)
	}
	if !idx.AdmitsWrite(subj.Digest.String(), subj.Argv, path) {
		return Secret{}, ErrDenied
	}
	return b.Provider.Put(ctx, path, data)
}
