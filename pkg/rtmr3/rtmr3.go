// Package rtmr3 pins the c8s per-workload RTMR[3] measurement convention.
// It is the single source of truth shared by the in-guest measurer
// (internal/cmds/rtmr3measurer) and any verifier that recomputes the
// expected register value from a set of deployed image digests — the two
// sides MUST both build on this package so the convention cannot drift.
// See docs/kata-guest-base.md "Per-workload RTMR[3] measurement".
package rtmr3

import "crypto/sha512"

// Size is the byte length of RTMR[3] and of every event (SHA-384).
const Size = 48

// Zero is the register's reset value at guest boot.
var Zero [Size]byte

// Event maps one workload image to its RTMR[3] event: SHA384 of the
// canonical digest string "sha256:<64-hex>".
func Event(canonicalDigest string) [Size]byte {
	return sha512.Sum384([]byte(canonicalDigest))
}

// Extend folds one event into a register value, mirroring the hardware
// TDG.MR.RTMR.EXTEND: new = SHA384(reg ‖ event).
func Extend(reg, event [Size]byte) [Size]byte {
	h := sha512.New384()
	h.Write(reg[:])
	h.Write(event[:])
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ForOperatorKey computes the RTMR[3] value a guest reports after the
// measured initrd extends the zeroed register once with SHA-384 of the
// operator public key (the PEM bytes staged on the opkeydata disk):
//
//	RTMR[3] = SHA384( 0x00*48 ‖ SHA384(pubkey) )
//
// Both sides of the credential-release flow — the in-guest service checking
// its own register and the operator computing the expectation offline — MUST
// build on this function so the binding cannot drift.
func ForOperatorKey(pubkey []byte) [Size]byte {
	return Extend(Zero, sha512.Sum384(pubkey))
}

// FromDigests computes the expected RTMR[3] after measuring the given
// canonical image digests in order, starting from Zero. Each DISTINCT
// image is extended exactly once (the measurer dedups restarts/replicas
// before extending); callers pass the deduped, ordered set.
func FromDigests(canonicalDigests []string) [Size]byte {
	reg := Zero
	for _, d := range canonicalDigests {
		reg = Extend(reg, Event(d))
	}
	return reg
}
