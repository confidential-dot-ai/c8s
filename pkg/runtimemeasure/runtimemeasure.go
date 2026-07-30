// Package runtimemeasure pins the c8s conventions for runtime measurement:
// what a guest extends into its runtime measurement register after launch,
// and in what order. It is the single source of truth shared by the in-guest
// measurer, the guest initrd's operator-key binding, and any verifier that
// recomputes the expected register value — every side MUST build on this
// package so the conventions cannot drift.
//
// Runtime measurement is the counterpart to launch measurement. A launch
// measurement (MRTD on Intel TDX, the launch digest on AMD SEV-SNP) covers
// what booted and is fixed at launch. A runtime measurement register is
// hardware-append-only and records what happened afterwards, so it can carry
// identity a launch measurement cannot: who operates this node, and which
// workloads it admitted.
//
// c8s extends two distinct kinds of value, in this order:
//
//   - the operator-key seed, written once by the measured initrd before
//     switch_root (ForOperatorKey), then
//   - zero or more per-workload image extends chained on top (Event).
//
// A verifier cannot interpret the register for either purpose without knowing
// the seed, so a node launched with an operator key must be verified with
// FromDigestsSeeded(ForOperatorKey(pub), …) rather than FromDigests.
//
// This package is deliberately vendor-neutral: it is arithmetic over digests
// and says nothing about where the register lives. Today the only backing
// hardware is Intel TDX RTMR[3] — SEV-SNP has no equivalent runtime-extend
// register — so the code that reads or writes the register is TDX-specific
// (internal/cmds/rtmr3measurer, credrelease, the confos initrd) while the
// convention it implements is not. See docs/kata-guest-base.md
// "Per-workload RTMR[3] measurement".
package runtimemeasure

import (
	"crypto/sha512"
	"errors"
	"regexp"
	"strings"
)

// Size is the byte length of the register and of every event (SHA-384).
const Size = 48

// Zero is the register's reset value at guest boot.
var Zero [Size]byte

// Event maps one workload image to its measurement event: SHA384 of the
// canonical digest string "sha256:<64-hex>".
func Event(canonicalDigest string) [Size]byte {
	return sha512.Sum384([]byte(canonicalDigest))
}

// Extend folds one event into a register value, mirroring the hardware extend
// primitive (on TDX, TDG.MR.RTMR.EXTEND): new = SHA384(reg ‖ event).
func Extend(reg, event [Size]byte) [Size]byte {
	h := sha512.New384()
	h.Write(reg[:])
	h.Write(event[:])
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// FromDigests computes the expected register value after measuring the given
// canonical image digests in order, starting from Zero. Each DISTINCT
// image is extended exactly once (the measurer dedups restarts/replicas
// before extending); callers pass the deduped, ordered set.
//
// Use FromDigestsSeeded for a node launched with an operator key: its
// register does not start from Zero.
func FromDigests(canonicalDigests []string) [Size]byte {
	return FromDigestsSeeded(Zero, canonicalDigests)
}

// FromDigestsSeeded is FromDigests starting from an arbitrary register
// value, so per-workload extends can chain onto an operator-key seed:
//
//	FromDigestsSeeded(ForOperatorKey(pub), digests)
func FromDigestsSeeded(seed [Size]byte, canonicalDigests []string) [Size]byte {
	reg := seed
	for _, d := range canonicalDigests {
		reg = Extend(reg, Event(d))
	}
	return reg
}

// ForOperatorKey computes the register value as it reads back on a node
// launched with an operator key and no per-workload extends:
//
//	reg = SHA384( 0x00*48 ‖ SHA384(pubkey) )
//
// The guest initrd hashes the operator public key off the opkeydata disk and
// extends that digest into the register before switch_root, so the operator
// can verify offline that the node trusts only their key. cred-release
// re-derives the same value to confirm the staged on-disk pubkey is the
// measured one.
//
// pubkey is the EXACT bytes the initrd hashed — the pubkey file verbatim, as
// written by `openssl ec -pubout` (PEM text, trailing newline included). Any
// re-encoding, re-wrapping, or stripped newline yields a different digest and
// a silent verification failure, so pass file bytes through unmodified rather
// than round-tripping through a PEM parser.
func ForOperatorKey(pubkey []byte) [Size]byte {
	return Extend(Zero, sha512.Sum384(pubkey))
}

// hex64 matches the lowercase hex body of a sha256 digest.
var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// CanonicalDigest normalizes an image reference to the exact "sha256:<64-hex>"
// string Event hashes. It accepts a bare digest, a "sha256:"-prefixed one, or
// any "<ref>@sha256:<hex>", and folds case.
//
// A reference carrying no digest — a bare tag — is refused: a tag is not
// content-bound, so it cannot name what was measured, and silently accepting
// one would produce a register value for an image nobody can identify. Every
// side that turns references into extends MUST go through this, so the
// measurer and its verifiers cannot disagree about what was hashed.
func CanonicalDigest(reference string) (string, error) {
	s := strings.TrimSpace(reference)
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "sha256:")
	if !hex64.MatchString(s) {
		return "", errors.New("not a sha256:<64hex> digest (images must be pinned by digest; a tag is not content-bound)")
	}
	return "sha256:" + s, nil
}
