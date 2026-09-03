// Package runtimemeasure pins the c8s conventions for runtime measurement:
// what a guest extends into its runtime measurement register after launch,
// and in what order. It is the single source of truth shared by the in-guest
// measurer, the guest initrd's operator-key binding, the node's policy
// measurer, and any verifier that recomputes the expected register value —
// every side MUST build on this package so the conventions cannot drift.
//
// Runtime measurement is the counterpart to launch measurement. A launch
// measurement (MRTD on Intel TDX, the launch digest on AMD SEV-SNP) covers
// what booted and is fixed at launch. A runtime measurement register is
// hardware-append-only and records what happened afterwards, so it can carry
// identity a launch measurement cannot: which key the node was launched to
// trust, which mode the node runs in, and which workloads it admitted.
//
// A node's register takes one of two shapes, selected by an explicit mode
// event that the measured node image extends before containerd starts:
//
//   - dynamic: [operator-key seed] → ModeDynamic → [workload extends]. The
//     seed is written once by the measured initrd before switch_root
//     (ForOperatorKey) and is absent (the register stays Zero) on a node
//     launched without an operator key. ForDynamic(seed) is the register after
//     the mode event; per-workload image extends (Event) chain on top.
//   - static: Zero → ModeStatic → PolicyEvent(index). There is no operator-key
//     seed and no workload extend: the register commits the policy bundle the
//     node booted with (ForStaticAllowlist) and nothing else.
//
// The mode event is what keeps the two shapes apart: without it a dynamic
// node, where cluster-admin is node root, could extend the static events
// itself and pass a static verifier. A verifier cannot interpret the register
// without knowing the shape, so a dynamic node launched with an operator key
// must be verified with FromDigestsSeeded(ForDynamic(ForOperatorKey(pub)), …)
// rather than FromDigests.
//
// This package is deliberately vendor-neutral: it is arithmetic over digests
// and says nothing about where the register lives. The register-backed
// convention above runs on Intel TDX RTMR[3]. SEV-SNP has no runtime-extend
// register, so on SNP only the operator-key half of the convention exists:
// the launcher commits the key digest into the report's immutable HOSTDATA
// field at launch (HostDataForOperatorKey), and mode events and per-workload
// extends do not exist — FromDigestsSeeded/Event/ForDynamic/ForStaticAllowlist
// remain TDX-only. The code that reads or writes the TDX register is
// TDX-specific (internal/tdxrtmr and its callers, the guest initrd) while the
// convention it implements is not. See docs/kata-guest-base.md "Per-workload
// RTMR[3] measurement".
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
// value, so per-workload extends can chain onto the dynamic-mode register of
// an operator-key-bound node:
//
//	FromDigestsSeeded(ForDynamic(ForOperatorKey(pub)), digests)
func FromDigestsSeeded(seed [Size]byte, canonicalDigests []string) [Size]byte {
	reg := seed
	for _, d := range canonicalDigests {
		reg = Extend(reg, Event(d))
	}
	return reg
}

// ForOperatorKey computes the operator-key seed: the register value as it
// reads back at switch_root on a node launched with an operator key, before
// the node image extends the mode event:
//
//	reg = SHA384( 0x00*48 ‖ SHA384(pubkey) )
//
// The guest initrd hashes the operator public key off the opkeydata disk and
// extends that digest into the register before switch_root, so the operator
// can verify offline that the node trusts only their key. The node image then
// extends ModeDynamic (see ForDynamic); cred-release and every verifier
// compare against that chained value, never the bare seed.
//
// pubkey is the EXACT bytes the initrd hashed — the pubkey file verbatim, as
// written by `openssl ec -pubout` (PKIX PEM text, armor and trailing newline
// included). Any re-encoding, re-wrapping, or stripped newline yields a
// different digest and a silent verification failure, so pass file bytes
// through unmodified rather than round-tripping through a PEM parser.
func ForOperatorKey(pubkey []byte) [Size]byte {
	return Extend(Zero, sha512.Sum384(pubkey))
}

// Mode events. Each is the SHA-384 of a fixed ASCII label (not Event, which
// takes a canonical image digest), so a label collision with an image digest
// or a policy event is impossible: the label namespaces are disjoint.
var (
	// ModeStatic is the event a static-allowlist node extends first. Label:
	// "c8s/rtmr3/mode/static/v1".
	ModeStatic = sha512.Sum384([]byte("c8s/rtmr3/mode/static/v1"))
	// ModeDynamic is the event a dynamic node extends on top of the
	// operator-key seed (or Zero). Label: "c8s/rtmr3/mode/dynamic/v1".
	ModeDynamic = sha512.Sum384([]byte("c8s/rtmr3/mode/dynamic/v1"))
)

// policyEventPrefix namespaces the policy event so its preimage can never be
// a mode label or an image digest string.
const policyEventPrefix = "c8s/rtmr3/policy/v1:"

// PolicyEvent maps a policy-bundle index to its measurement event:
// SHA384("c8s/rtmr3/policy/v1:" ‖ index). index is the bundle's canonical
// index document — the bytes pkg/policybundle Bundle.Index returns:
// encoding/json of map[string]string{name: "sha256:<hex>"} (keys sorted, no
// whitespace) — and is hashed verbatim.
func PolicyEvent(index []byte) [Size]byte {
	h := sha512.New384()
	h.Write([]byte(policyEventPrefix))
	h.Write(index)
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ForStaticAllowlist computes the register of a static-allowlist node:
//
//	reg = Extend(Extend(Zero, ModeStatic), PolicyEvent(index))
//
// A static node has no operator-key seed and runs no workload measurer, so
// the register equals this value for the life of the guest.
func ForStaticAllowlist(index []byte) [Size]byte {
	return Extend(Extend(Zero, ModeStatic), PolicyEvent(index))
}

// ForDynamic computes the register of a dynamic node after the node image
// extends the mode event: Extend(seed, ModeDynamic). seed is
// ForOperatorKey(pub) on a node launched with an operator key and Zero
// otherwise. Per-workload extends, where a measurer runs, chain on top via
// FromDigestsSeeded.
func ForDynamic(seed [Size]byte) [Size]byte {
	return Extend(seed, ModeDynamic)
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
