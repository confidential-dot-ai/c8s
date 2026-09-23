package policystate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Hashing domains. Every domain-separated hash and every signature covers
// domain || 0x00 || canonical, so bytes accepted in one role can never be
// replayed in another.
const (
	// DomainState covers a State statement.
	DomainState = "c8s.policystate/v1/state"
	// DomainChallenge covers a ChallengeBinding.
	DomainChallenge = "c8s.policystate/v1/challenge"
	// DomainAck covers every participant message (Enrollment, Ack, Completion).
	DomainAck = "c8s.policystate/v1/ack"
)

// hashLen is the length of a SHA-256 digest in bytes.
const hashLen = sha256.Size

// Hash returns sha256(domain || 0x00 || canonical). The separator byte cannot
// occur in a domain string, so no two domains share a preimage.
func Hash(domain string, canonical []byte) [hashLen]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(canonical)
	var out [hashLen]byte
	h.Sum(out[:0])
	return out
}

// FormatHash renders a hash as the wire form "sha256:<64 lowercase hex>".
func FormatHash(h [hashLen]byte) string {
	return "sha256:" + hex.EncodeToString(h[:])
}

// ParseHash parses the wire form produced by FormatHash. Uppercase hex is
// rejected: a hash is compared as a string throughout the protocol, so two
// spellings of one value would be two values.
func ParseHash(s string) ([hashLen]byte, error) {
	var out [hashLen]byte
	rest, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(rest) != 2*hashLen {
		return out, fmt.Errorf("hash %q: want sha256:<64 lowercase hex>", s)
	}
	if strings.ToLower(rest) != rest {
		return out, fmt.Errorf("hash %q: hex must be lowercase", s)
	}
	if _, err := hex.Decode(out[:], []byte(rest)); err != nil {
		return out, fmt.Errorf("hash %q: %w", s, err)
	}
	return out, nil
}

// ContentDigest names exact bytes: sha256 with no domain separation, so any
// party that fetched the object can reproduce it without knowing the protocol.
// It is the name of every public object — a policy document and a journal
// entry alike — and the digest a verifier pins.
func ContentDigest(data []byte) string {
	return FormatHash(sha256.Sum256(data))
}

// hashValue canonicalizes v and returns its domain-separated hash in wire form.
func hashValue(domain string, v any) (string, error) {
	canonical, err := Canonical(v)
	if err != nil {
		return "", err
	}
	return FormatHash(Hash(domain, canonical)), nil
}
