package coordinator

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// Publication is what one publish produced.
type Publication struct {
	Version       uint64
	PolicyDigest  string
	RequiresDrain bool
	LogHead       string
}

// CanPublish reports whether a publication would be accepted now. A caller that
// mutates its own store first uses it to refuse before touching anything: an
// update outstanding here means the store must not move either, or the next
// publication would name a document nobody approved.
func (c *Coordinator) CanPublish() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.canPublish()
}

func (c *Coordinator) canPublish() error {
	if c.update != nil {
		return fmt.Errorf("%w: version %d is still rolling out", ErrConflict, c.update.Version)
	}
	return nil
}

// Publish stores a policy document as the next version and opens the update
// that rolls it out.
//
// canonical must be the exact canonical bytes of a valid allowlist: the digest
// names those bytes, so a document that does not round-trip is refused rather
// than stored under a name no independent implementation would reproduce.
//
// Publication authorizes nothing. It widens the advertised bound to source-or-
// target, freezes the participant set that must acknowledge, and returns. With
// no participant enrolled the update switches and completes in this same
// transaction, which is what makes the first publication of a deployment
// immediately active.
func (c *Coordinator) Publish(canonical []byte, authorizedBy string) (Publication, error) {
	if authorizedBy == "" {
		return Publication{}, fmt.Errorf("%w: a publication must name who authorized it", ErrInvalid)
	}
	target, err := parsePolicy(canonical)
	if err != nil {
		return Publication{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.canPublish(); err != nil {
		return Publication{}, err
	}
	version := c.published + 1
	if version >= policystate.MaxCounter {
		return Publication{}, fmt.Errorf("%w: version counter exhausted", ErrConflict)
	}
	// A rule the source granted and the target does not is a permission some
	// running instance may still hold, so the bound stays at source-or-target
	// until every participant reports it gone. The first policy removes nothing.
	var source *allowlist.Allowlist
	if c.published > 0 {
		if source, _, err = c.policy(c.publishedDigest); err != nil {
			return Publication{}, err
		}
	}
	requiresDrain := len(allowlist.Removed(source, target)) > 0
	digest := policystate.ContentDigest(canonical)

	err = c.write(func(a *appender) error {
		if _, err := putObject(a.tx, canonical); err != nil {
			return err
		}
		if err := a.add(policystate.EventPublished, policystate.PublishedPayload{
			Version:       version,
			SourceDigest:  c.publishedDigest,
			TargetDigest:  digest,
			RequiresDrain: requiresDrain,
			AuthorizedBy:  authorizedBy,
		}); err != nil {
			return err
		}
		if _, err := a.tx.Exec(
			`INSERT INTO "update" (id, version, source, target, requires_drain, switched) VALUES (1, ?, ?, ?, ?, 0)`,
			version, c.publishedDigest, digest, boolInt(requiresDrain)); err != nil {
			return err
		}
		if _, err := a.tx.Exec("INSERT INTO update_participants (boot_id) SELECT boot_id FROM participants"); err != nil {
			return err
		}
		return c.advance(a)
	})
	if err != nil {
		return Publication{}, err
	}
	c.published, c.publishedDigest = version, digest
	slog.Info("policy version published",
		"version", version, "policy_digest", digest, "requires_drain", requiresDrain,
		"authorized_by", authorizedBy, "switched", c.update == nil || c.update.Switched)
	return Publication{Version: version, PolicyDigest: digest, RequiresDrain: requiresDrain, LogHead: c.headDigest}, nil
}

// Active returns the policy admission, issuance and secret release run against:
// the parsed document, its exact stored bytes, its version and its digest.
//
// It is not the newest published version while an update is outstanding and
// unswitched — that is the whole point of the switch.
func (c *Coordinator) Active() (*allowlist.Allowlist, []byte, uint64, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	version, digest, err := c.active()
	if err != nil {
		return nil, nil, 0, "", err
	}
	doc, raw, err := c.policy(digest)
	if err != nil {
		return nil, nil, 0, "", err
	}
	return doc, raw, version, digest, nil
}

// ActiveVersion is the version in force, without loading the document: the
// cheap read a cache uses to decide whether to reload.
func (c *Coordinator) ActiveVersion() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	version, _, err := c.active()
	return version, err
}

// active returns the version and digest in force. Callers hold c.mu.
func (c *Coordinator) active() (uint64, string, error) {
	if c.update != nil && !c.update.Switched {
		// Version 1 cannot reach here: nothing can enroll before the first
		// publication, so the first update has an empty frozen set and switches
		// in the transaction that opens it.
		return c.update.Version - 1, c.update.SourceDigest, nil
	}
	if c.published == 0 {
		return 0, "", fmt.Errorf("no policy has been published yet: %w", ErrNotFound)
	}
	return c.published, c.publishedDigest, nil
}

// policy loads a stored policy object and parses it. Callers hold c.mu.
func (c *Coordinator) policy(digest string) (*allowlist.Allowlist, []byte, error) {
	raw, err := loadObject(c.db, digest)
	if err != nil {
		return nil, nil, err
	}
	doc, err := allowlist.ParseJSON(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("stored policy %s: %w", digest, err)
	}
	return doc, raw, nil
}

// parsePolicy rejects bytes that are not the canonical form of a valid policy
// document.
func parsePolicy(data []byte) (*allowlist.Allowlist, error) {
	parsed, err := allowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%w: policy: %v", ErrInvalid, err)
	}
	canonical, err := parsed.Canonical()
	if err != nil {
		return nil, fmt.Errorf("%w: policy: %v", ErrInvalid, err)
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: policy bytes are not canonical", ErrInvalid)
	}
	return parsed, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
