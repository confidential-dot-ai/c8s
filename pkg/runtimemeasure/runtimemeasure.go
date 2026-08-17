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
// identity a launch measurement cannot: which key the node was launched to
// trust, and which workloads it admitted.
//
// c8s extends two distinct kinds of value, in this order:
//
//   - the operator-key seed, written once by the measured initrd before
//     switch_root (ForOperatorKey), then
//   - zero or more per-workload image extends chained on top (Event).
//
// A verifier cannot interpret the register without knowing the seed, so a
// node launched with an operator key must be verified with
// FromDigestsSeeded(ForOperatorKey(pub), …) rather than FromDigests.
//
// This package is deliberately vendor-neutral: it is arithmetic over digests
// and says nothing about where the register lives. The register-backed
// convention above runs on Intel TDX RTMR[3]. SEV-SNP has no runtime-extend
// register, so on SNP only the operator-key half of the convention exists:
// the launcher commits the key digest into the report's immutable HOSTDATA
// field at launch (HostDataForOperatorKey), and per-workload extends do not
// exist — FromDigestsSeeded/Event remain TDX-only. The code that reads or
// writes the TDX register is TDX-specific (internal/cmds/rtmr3measurer,
// credrelease, the guest initrd) while the convention it implements is not.
// See docs/kata-guest-base.md "Per-workload RTMR[3] measurement".
package runtimemeasure

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
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
// written by `openssl ec -pubout` (PKIX PEM text, armor and trailing newline
// included). Any re-encoding, re-wrapping, or stripped newline yields a
// different digest and a silent verification failure, so pass file bytes
// through unmodified rather than round-tripping through a PEM parser.
func ForOperatorKey(pubkey []byte) [Size]byte {
	return Extend(Zero, sha512.Sum384(pubkey))
}

// HostDataSize is the byte length of the SNP HOSTDATA field, and so of the
// operator-key binding value on SNP (SHA-256).
const HostDataSize = 32

// HostDataForOperatorKey computes the SNP launch-time operator-key binding:
// the value the launcher commits as HOSTDATA when launching a node CVM for
// this key:
//
//	HOSTDATA = SHA256(pubkey)
//
// It is the SNP analog of ForOperatorKey. SEV-SNP has no runtime-extend
// register, so instead of the measured initrd extending the key digest into
// RTMR[3] after launch, the (untrusted) launcher commits it into the report's
// immutable HOSTDATA field at launch. The trust argument is unchanged: the
// host could set any value, but a verifier that checks HOSTDATA against the
// key it expects rejects a wrong-key launch, exactly as it would reject a
// wrong RTMR[3]. A VM launched without an operator key carries all-zero
// HOSTDATA, which no SHA-256 output equals.
//
// pubkey is the EXACT bytes staged as the opkeydata disk's pubkey file (see
// ForOperatorKey); any re-encoding yields a different digest.
func HostDataForOperatorKey(pubkey []byte) [HostDataSize]byte {
	return sha256.Sum256(pubkey)
}

// CanonicalDigest strictly canonicalizes an image reference to the
// "sha256:<64-lowercase-hex>" form Event hashes. It accepts a bare canonical
// digest or a digest-pinned reference ("name@sha256:<hex>") and rejects
// everything else: tag references, uppercase hex, wrong digest lengths, and
// non-sha256 algorithms. Measurement events are byte-exact over this string,
// so any laxness here (case folding, tag resolution) would let two verifiers
// disagree about the same image.
func CanonicalDigest(ref string) (string, error) {
	digest := ref
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		if i == 0 {
			return "", fmt.Errorf("image ref %q has an empty name before %q", ref, "@")
		}
		digest = ref[i+1:]
	}
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		return "", fmt.Errorf("%q is not digest-pinned: want \"sha256:<64-hex>\" or \"name@sha256:<64-hex>\" (tags and non-sha256 algorithms are rejected)", ref)
	}
	if len(hexPart) != 64 {
		return "", fmt.Errorf("%q: digest is %d hex chars, want 64", ref, len(hexPart))
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("%q: digest is not 64 lowercase hex chars", ref)
		}
	}
	return "sha256:" + hexPart, nil
}
