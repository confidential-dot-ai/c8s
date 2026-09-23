package allowlist

import (
	"errors"
	"fmt"
	"sync"
)

// ErrBlocked is a mutation refused because the publisher will not accept a
// publication now: an update is still rolling out. The store is untouched, so
// the caller retries the whole write once the rollout finishes.
var ErrBlocked = errors.New("publication is blocked")

// ErrNotPublished is a mutation that committed to the store but could not be
// published. It is the one failure that leaves the two out of step.
var ErrNotPublished = errors.New("allowlist updated but not published")

// Publisher records a policy document as a new published version.
type Publisher interface {
	// CanPublish reports whether a publication would be accepted now. A
	// mutation asks before it commits: publishing a document the deployment is
	// mid-rollout on would make the advertised bound ambiguous, and the store
	// must not move either, or the next publication would carry an edit nobody
	// meant to make then.
	CanPublish() error
	Publish(canonical []byte, authorizedBy string) error
}

// ActivePolicy supplies the document in force and the version that names it.
type ActivePolicy interface {
	ActiveBytes() ([]byte, uint64, error)
}

// Publications connects the allowlist endpoints to the coordinator: GET
// /allowlist serves the ACTIVE document, and every mutation publishes the
// document it produced.
type Publications struct {
	// Publisher records a document as the next version.
	Publisher Publisher
	// Active is the document GET /allowlist serves. A published version the
	// coordinator has not switched to must not reach an enforcer that follows
	// this endpoint, or it would admit new rules before the barrier is in
	// place.
	Active ActivePolicy
	// AuthorizedBy names the authority behind an operator write, as the
	// publication records it.
	AuthorizedBy string

	// mu serializes the whole check-mutate-publish sequence. Two operator
	// writes may arrive at once, but their publications must follow the order
	// they committed in, or the published head would name a document the store
	// does not hold.
	mu sync.Mutex
}

// Apply refuses, mutates and publishes under one lock. mutate runs only once
// the publisher has agreed to take the result, so a write that arrives during a
// rollout leaves the store exactly as it was.
//
// A failure from mutate is returned as it came, for the caller to map. A
// failure to publish afterwards leaves the store ahead of the journal; the next
// successful mutation republishes the whole document, so the two converge
// without operator action.
func (p *Publications) Apply(store *Store, mutate func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.Publisher.CanPublish(); err != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	if err := mutate(); err != nil {
		return err
	}
	doc, _, err := store.LoadAll()
	if err != nil {
		return fmt.Errorf("%w: read back allowlist: %w", ErrNotPublished, err)
	}
	canonical, err := doc.Canonical()
	if err != nil {
		return fmt.Errorf("%w: canonicalize allowlist: %w", ErrNotPublished, err)
	}
	if err := p.Publisher.Publish(canonical, p.AuthorizedBy); err != nil {
		return fmt.Errorf("%w: %w", ErrNotPublished, err)
	}
	return nil
}
