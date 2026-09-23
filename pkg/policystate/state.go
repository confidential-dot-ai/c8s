package policystate

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"time"
)

// Nonce bounds for the state challenge. The floor keeps a verifier's nonce
// unguessable; the ceiling keeps an unauthenticated request from making CDS
// sign an arbitrary blob.
const (
	MinNonceLen = 16
	MaxNonceLen = 64
)

// Update is the one outstanding policy move. V1 serializes updates, so this is
// a single value rather than a list: overlapping moves would make the
// advertised bound ambiguous.
//
// Switched says the coordinator has authorized the target for admission,
// issuance and secret release. It does not mean the source's permissions are
// gone: that is what RequiresDrain tracks, and it holds until the coordinator
// appends a drained entry and clears the update.
type Update struct {
	Version       uint64 `json:"version"`
	SourceDigest  string `json:"source_digest,omitempty"`
	TargetDigest  string `json:"target_digest"`
	RequiresDrain bool   `json:"requires_drain"`
	Switched      bool   `json:"switched"`
}

// State is the effective-state statement CDS signs. It is the upper bound on
// what may be executing in the attested participants: the policies named by
// Bound, and nothing else.
//
// Update is always present — null when no update is outstanding — so a
// verifier can tell "nothing in flight" from a field a lossy encoder dropped.
type State struct {
	Protocol      string  `json:"protocol"`
	DeploymentID  string  `json:"deployment_id"`
	Authority     string  `json:"authority"`
	LogHead       string  `json:"log_head"`
	LogPosition   uint64  `json:"log_position"`
	ActiveVersion uint64  `json:"active_version"`
	ActiveDigest  string  `json:"active_digest"`
	Update        *Update `json:"update"`
	IssuedAt      string  `json:"issued_at"`
}

// SignedState is a State with the CDS signature over it. PublicKey carries the
// signing key itself: a verifier checks that its fingerprint is the authority
// the statement names, then decides whether to trust that authority.
type SignedState struct {
	Statement State  `json:"statement"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// ChallengeBinding ties a signed statement to one verifier's nonce. Signing
// the state alone proves which statement an ingress used, not that it is
// current; the nonce is what makes a replayed statement detectable.
type ChallengeBinding struct {
	Nonce       string `json:"nonce"`
	Authority   string `json:"authority"`
	LogHead     string `json:"log_head"`
	LogPosition uint64 `json:"log_position"`
}

// ChallengedState is the challenge endpoint's response: the current signed
// state plus a second signature binding it to the caller's nonce.
type ChallengedState struct {
	SignedState
	Challenge          ChallengeBinding `json:"challenge"`
	ChallengeSignature string           `json:"challenge_signature"`
}

// Bound is the advertised policy bound: every policy digest a participant on
// the protected path may still be executing under, sorted and deduplicated.
//
// With no update outstanding that is the active policy alone. An update that
// removes nothing widens nothing, so the bound is its target. An update that
// removes permissions conservatively covers both policies until the drain
// completes, whatever the switch has already done.
func Bound(s State) []string {
	var out []string
	switch {
	case s.Update == nil:
		out = []string{s.ActiveDigest}
	case s.Update.RequiresDrain:
		out = []string{s.Update.SourceDigest, s.Update.TargetDigest}
	default:
		out = []string{s.Update.TargetDigest}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// StateHash is H(S): the value the router binds into per-session evidence, so
// a verifier can tell which statement the ingress actually used.
func StateHash(s State) (string, error) {
	return hashValue(DomainState, s)
}

// SignState validates the statement and signs it. Validation happens before
// signing so CDS cannot put its name on a statement a verifier must reject,
// and the statement's authority must be the signing key's own fingerprint.
func SignState(priv ed25519.PrivateKey, s State) (SignedState, error) {
	if err := ValidateState(s); err != nil {
		return SignedState{}, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return SignedState{}, fmt.Errorf("sign state: private key is not ed25519")
	}
	fingerprint, err := AuthorityFingerprint(pub)
	if err != nil {
		return SignedState{}, err
	}
	if fingerprint != s.Authority {
		return SignedState{}, fmt.Errorf("sign state: statement names authority %s, signing key is %s", s.Authority, fingerprint)
	}
	encoded, err := EncodeAuthorityKey(pub)
	if err != nil {
		return SignedState{}, err
	}
	canonical, err := Canonical(s)
	if err != nil {
		return SignedState{}, err
	}
	sig, err := Sign(priv, DomainState, canonical)
	if err != nil {
		return SignedState{}, err
	}
	return SignedState{Statement: s, PublicKey: encoded, Signature: sig}, nil
}

// VerifySignedState checks the statement, that the carried key is the
// authority the statement names, and the signature under that key.
//
// It says nothing about whether the authority deserves trust: pinning it,
// learning it over an attested channel or refusing it outright is the caller's
// decision.
func VerifySignedState(s SignedState) error {
	if err := ValidateState(s.Statement); err != nil {
		return err
	}
	pub, err := DecodeAuthorityKey(s.PublicKey)
	if err != nil {
		return fmt.Errorf("signed state: %w", err)
	}
	fingerprint, err := AuthorityFingerprint(pub)
	if err != nil {
		return fmt.Errorf("signed state: %w", err)
	}
	if fingerprint != s.Statement.Authority {
		return fmt.Errorf("signed state: carried key is %s, statement names authority %s", fingerprint, s.Statement.Authority)
	}
	canonical, err := Canonical(s.Statement)
	if err != nil {
		return err
	}
	if err := Verify(pub, DomainState, canonical, s.Signature); err != nil {
		return fmt.Errorf("signed state: %w", err)
	}
	return nil
}

// SignChallenge answers a verifier's nonce with the signed statement plus a
// binding over it. The binding is built from the statement rather than taken
// from the caller, so the two can never disagree.
func SignChallenge(priv ed25519.PrivateKey, s SignedState, nonce []byte) (ChallengedState, error) {
	if len(nonce) < MinNonceLen || len(nonce) > MaxNonceLen {
		return ChallengedState{}, fmt.Errorf("challenge: nonce is %d bytes, want %d..%d", len(nonce), MinNonceLen, MaxNonceLen)
	}
	binding := ChallengeBinding{
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce),
		Authority:   s.Statement.Authority,
		LogHead:     s.Statement.LogHead,
		LogPosition: s.Statement.LogPosition,
	}
	canonical, err := Canonical(binding)
	if err != nil {
		return ChallengedState{}, err
	}
	sig, err := Sign(priv, DomainChallenge, canonical)
	if err != nil {
		return ChallengedState{}, err
	}
	return ChallengedState{SignedState: s, Challenge: binding, ChallengeSignature: sig}, nil
}

// VerifyChallengedState checks both signatures and that the binding names the
// caller's nonce and the statement it arrived with. A response whose binding
// points at a different head is a replay of an older challenge.
func VerifyChallengedState(cs ChallengedState, nonce []byte) error {
	if err := VerifySignedState(cs.SignedState); err != nil {
		return err
	}
	got, err := base64.RawURLEncoding.DecodeString(cs.Challenge.Nonce)
	if err != nil {
		return fmt.Errorf("challenge: nonce is not unpadded base64url: %w", err)
	}
	if subtle.ConstantTimeCompare(got, nonce) != 1 {
		return fmt.Errorf("challenge: nonce does not match the one sent")
	}
	st := cs.Statement
	if cs.Challenge.Authority != st.Authority || cs.Challenge.LogHead != st.LogHead || cs.Challenge.LogPosition != st.LogPosition {
		return fmt.Errorf("challenge: binding does not match the statement it accompanies")
	}
	pub, err := DecodeAuthorityKey(cs.PublicKey)
	if err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	canonical, err := Canonical(cs.Challenge)
	if err != nil {
		return err
	}
	if err := Verify(pub, DomainChallenge, canonical, cs.ChallengeSignature); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	return nil
}

// ValidateState checks a statement's shape: the protocol, the counters, the
// hash forms and a fully populated update when there is one.
func ValidateState(s State) error {
	if s.Protocol != Protocol {
		return fmt.Errorf("state: unknown protocol %q (want %q)", s.Protocol, Protocol)
	}
	if s.DeploymentID == "" {
		return fmt.Errorf("state: deployment id is required")
	}
	if _, err := ParseHash(s.Authority); err != nil {
		return fmt.Errorf("state: authority: %w", err)
	}
	if _, err := ParseHash(s.LogHead); err != nil {
		return fmt.Errorf("state: log head: %w", err)
	}
	if s.LogPosition < 1 || s.LogPosition >= MaxCounter {
		return fmt.Errorf("state: log position %d is out of range [1, 2^53)", s.LogPosition)
	}
	if s.ActiveVersion < 1 || s.ActiveVersion >= MaxCounter {
		return fmt.Errorf("state: active version %d is out of range [1, 2^53)", s.ActiveVersion)
	}
	if _, err := ParseHash(s.ActiveDigest); err != nil {
		return fmt.Errorf("state: active digest: %w", err)
	}
	if err := validateUpdate(s.Update); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, s.IssuedAt); err != nil {
		return fmt.Errorf("state: issued_at %q is not RFC3339", s.IssuedAt)
	}
	return nil
}

// validateUpdate rejects a half-populated update: a nil pointer is the only
// way to say "nothing outstanding". A drain accounts for permissions the
// source held, so an update that requires one must name that source.
func validateUpdate(u *Update) error {
	if u == nil {
		return nil
	}
	if u.Version < 1 || u.Version >= MaxCounter {
		return fmt.Errorf("state: update version %d is out of range [1, 2^53)", u.Version)
	}
	if _, err := ParseHash(u.TargetDigest); err != nil {
		return fmt.Errorf("state: update target digest: %w", err)
	}
	if u.SourceDigest != "" {
		if _, err := ParseHash(u.SourceDigest); err != nil {
			return fmt.Errorf("state: update source digest: %w", err)
		}
	} else if u.RequiresDrain {
		return fmt.Errorf("state: update requires a drain but names no source digest")
	}
	return nil
}
