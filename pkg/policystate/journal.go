package policystate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// EventType names what a journal entry records.
type EventType string

// Journal event types. They are the only two events a verifier has to
// interpret: publication widens the advertised bound to source-or-target, and
// a drain narrows it back to the target.
const (
	// EventPublished records an operator-authorized policy version.
	EventPublished EventType = "published"
	// EventDrained records that no participant holds the source policy's
	// removed permissions any more.
	EventDrained EventType = "drained"
)

// AuthorizedBySeed marks a publication made by the deployment's own bootstrap
// rather than by an operator key.
const AuthorizedBySeed = "seed"

// Entry is one record in the append-only journal. Parent chains it to its
// predecessor, so a verifier that holds a checkpoint can tell a continuation
// of its own history from a fork or a restored snapshot.
//
// Time is informational: CDS has no trustworthy wall clock, and nothing in the
// protocol orders entries by it.
type Entry struct {
	Protocol  string          `json:"protocol"`
	Authority string          `json:"authority"`
	Position  uint64          `json:"position"`
	Parent    string          `json:"parent,omitempty"`
	Type      EventType       `json:"type"`
	Time      string          `json:"time"`
	Payload   json.RawMessage `json:"payload"`
}

// PublishedPayload records a stored, immutable policy and who authorized it.
// Publication is not activation: nothing admits the target's new permissions
// until the coordinator says every participant's barrier is in place.
//
// RequiresDrain is false when the target still contains every rule of the
// source, which is the case where the advertised bound is the target alone.
type PublishedPayload struct {
	Version       uint64 `json:"version"`
	SourceDigest  string `json:"source_digest,omitempty"`
	TargetDigest  string `json:"target_digest"`
	RequiresDrain bool   `json:"requires_drain"`
	AuthorizedBy  string `json:"authorized_by"`
}

// DrainedPayload closes an update that removed permissions: every participant
// reported the target applied and nothing still holding a removed rule.
type DrainedPayload struct {
	Version uint64 `json:"version"`
}

// newPayload returns a fresh pointer to the payload struct an event type
// carries. It is the single list of known types: ValidateEntry rejects
// anything absent from it.
func newPayload(t EventType) (any, bool) {
	switch t {
	case EventPublished:
		return &PublishedPayload{}, true
	case EventDrained:
		return &DrainedPayload{}, true
	default:
		return nil, false
	}
}

// EntryDigest is the chain link and the name of an entry: it is what Parent
// holds, the path an entry is fetched by, and what a state statement's LogHead
// commits to. It is a plain content address over the canonical entry.
func EntryDigest(e Entry) (string, error) {
	canonical, err := Canonical(e)
	if err != nil {
		return "", err
	}
	return ContentDigest(canonical), nil
}

// NewEntryAt builds the next entry of a journal: it fills the protocol, the
// position, the parent link and the timestamp, canonicalizes the payload and
// validates the result.
//
// prev is the current head and prevDigest its EntryDigest; both are empty only
// for the very first entry of a deployment. authority is the fingerprint of
// the key signing state when the entry is appended; a CDS restart changes it
// without breaking the chain.
func NewEntryAt(prev *Entry, prevDigest, authority string, typ EventType, payload any, at time.Time) (Entry, error) {
	if (prev == nil) != (prevDigest == "") {
		return Entry{}, fmt.Errorf("new entry: prev and prevDigest must be given together")
	}
	position := uint64(1)
	if prev != nil {
		head, err := EntryDigest(*prev)
		if err != nil {
			return Entry{}, err
		}
		if head != prevDigest {
			return Entry{}, fmt.Errorf("new entry: prevDigest %s is not the digest of prev (%s)", prevDigest, head)
		}
		position = prev.Position + 1
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return Entry{}, fmt.Errorf("new entry: payload: %w", err)
	}
	e := Entry{
		Protocol:  Protocol,
		Authority: authority,
		Position:  position,
		Parent:    prevDigest,
		Type:      typ,
		Time:      at.UTC().Format(time.RFC3339),
		Payload:   canonical,
	}
	if err := ValidateEntry(e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// DecodePayload parses an entry's payload as T, strictly. Use the payload type
// the entry's Type calls for; a mismatch fails on the unknown fields.
func DecodePayload[T any](e Entry) (T, error) {
	var out T
	if err := Decode(e.Payload, &out); err != nil {
		return out, fmt.Errorf("entry payload: %w", err)
	}
	return out, nil
}

// ValidateEntry checks one entry in isolation: the protocol, the authority
// fingerprint, a 1-based position, the parent rule (only the first entry has
// none), a known event type, and a payload that parses as that type's struct
// and is already canonical.
//
// It cannot check that a chain is dense or that a parent exists — that is the
// store's job — but an entry rejected here can never enter one.
func ValidateEntry(e Entry) error {
	if e.Protocol != Protocol {
		return fmt.Errorf("entry: unknown protocol %q (want %q)", e.Protocol, Protocol)
	}
	if _, err := ParseHash(e.Authority); err != nil {
		return fmt.Errorf("entry: authority: %w", err)
	}
	if e.Position < 1 || e.Position >= MaxCounter {
		return fmt.Errorf("entry: position %d is out of range [1, 2^53)", e.Position)
	}
	if e.Position == 1 {
		if e.Parent != "" {
			return fmt.Errorf("entry: position 1 has parent %s, want none", e.Parent)
		}
	} else if _, err := ParseHash(e.Parent); err != nil {
		return fmt.Errorf("entry: parent: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, e.Time); err != nil {
		return fmt.Errorf("entry: time %q is not RFC3339", e.Time)
	}
	payload, ok := newPayload(e.Type)
	if !ok {
		return fmt.Errorf("entry: unknown type %q", e.Type)
	}
	if err := Decode(e.Payload, payload); err != nil {
		return fmt.Errorf("entry %s payload: %w", e.Type, err)
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return fmt.Errorf("entry %s payload: %w", e.Type, err)
	}
	if !bytes.Equal(canonical, e.Payload) {
		return fmt.Errorf("entry %s payload is not canonical: stored %s, canonical %s", e.Type, e.Payload, canonical)
	}
	return nil
}
