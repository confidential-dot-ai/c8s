package runtimemeasure

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Golden vectors pin the convention. If any of these change, the measurer
// and every verifier disagree on RTMR[3] — treat a failure here as a
// breaking change to the attestation contract, not a test to update.
func TestConventionGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  [Size]byte
		want string
	}{
		{"Event(A)", Event(digestA),
			"a3f24413601f0cebf6316f0e499927cbf4adae24d5421f94abdc135fa464bbbb2afb7075b075976eff5379cd25c3f8f2"},
		{"FromDigests[A]", FromDigests([]string{digestA}),
			"c22e78b178c845f91bdc8f575cd3e3b058a7903892807f81129f878df35bdf6566bd18dbcc5dce9177963b1d0e2889f3"},
		{"FromDigests[A,B]", FromDigests([]string{digestA, digestB}),
			"6e06070a4178ba9617ce1598f0e749a05c2e0b9c59e74236265f04d505348e203204ff3a7f920009b87ab272b34c3146"},
	} {
		if got := hex.EncodeToString(tc.got[:]); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestFromDigestsEmptyIsZero(t *testing.T) {
	if FromDigests(nil) != Zero {
		t.Error("FromDigests(nil) must equal the boot value Zero")
	}
}

func TestExtendMatchesFold(t *testing.T) {
	step := Extend(Extend(Zero, Event(digestA)), Event(digestB))
	if step != FromDigests([]string{digestA, digestB}) {
		t.Error("Extend composition disagrees with FromDigests")
	}
}

// TestForOperatorKeyMatchesHardware pins the operator-key seed to a value read
// back off real TDX hardware: RTMR[3] as reported by the b300-node-1 CVM
// launched 2026-07-28 with a P-256 operator key whose PEM file hashes to
// keyDigest. A failure here means the initrd, cred-release, and this package
// disagree about the binding — an attestation-contract break, not a stale test.
func TestForOperatorKeyMatchesHardware(t *testing.T) {
	const (
		keyDigest = "3e7ff02c15e2c5b2bedcc6ce041a3ab6d1f3b1417a7d459e8b866902c72e3ca676a84a5dacb044e077590da1bbff1cc2"
		wantRTMR3 = "a9b91d920971de864899fb5925c4b5230bf88750dd59866d8d34aeb975e86761ea7488ade961908d9595b6202c9e6470"
	)
	dig, err := hex.DecodeString(keyDigest)
	if err != nil {
		t.Fatalf("decode keyDigest: %v", err)
	}
	// ForOperatorKey hashes the key itself; here the digest is already known,
	// so extend it directly and check the two agree on the second step.
	var event [Size]byte
	copy(event[:], dig)
	reg := Extend(Zero, event)
	if got := hex.EncodeToString(reg[:]); got != wantRTMR3 {
		t.Errorf("Extend(Zero, keyDigest) = %s, want %s (hardware-confirmed)", got, wantRTMR3)
	}
}

// ForOperatorKey must be exactly one extend of the key's SHA-384, so a
// verifier can chain per-workload extends onto it.
func TestForOperatorKeyIsSingleExtendOfKeyDigest(t *testing.T) {
	pub := []byte("-----BEGIN PUBLIC KEY-----\nnot a real key\n-----END PUBLIC KEY-----\n")
	if ForOperatorKey(pub) != Extend(Zero, sha512.Sum384(pub)) {
		t.Error("ForOperatorKey must equal Extend(Zero, SHA384(pubkey))")
	}
}

// The seed is over the EXACT bytes supplied: a re-wrapped or newline-stripped
// PEM is a different key as far as RTMR[3] is concerned. Pinning that here
// makes the footgun a deliberate choice rather than a surprise.
func TestForOperatorKeyIsByteExact(t *testing.T) {
	withNewline := []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
	withoutNewline := withNewline[:len(withNewline)-1]
	if ForOperatorKey(withNewline) == ForOperatorKey(withoutNewline) {
		t.Error("ForOperatorKey must not normalize its input; a trailing newline changes the seed")
	}
}

func TestFromDigestsSeededFromZeroMatchesFromDigests(t *testing.T) {
	digests := []string{digestA, digestB}
	if FromDigestsSeeded(Zero, digests) != FromDigests(digests) {
		t.Error("FromDigestsSeeded(Zero, …) must equal FromDigests(…)")
	}
}

// The whole point of the seed: on an operator-key-bound node, per-workload
// extends chain onto it, so a verifier that starts from Zero gets the wrong
// answer.
func TestFromDigestsSeededChainsOntoOperatorKey(t *testing.T) {
	pub := []byte("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")
	seed := ForOperatorKey(pub)

	got := FromDigestsSeeded(seed, []string{digestA})
	if want := Extend(seed, Event(digestA)); got != want {
		t.Error("FromDigestsSeeded must extend from the seed")
	}
	if got == FromDigests([]string{digestA}) {
		t.Error("seeded and unseeded results must differ, else the seed is being ignored")
	}
}

// CanonicalDigest is the single normalization every side runs before hashing,
// so what the measurer extends and what a verifier recomputes cannot differ.
func TestCanonicalDigest(t *testing.T) {
	const hexBody = "81a9c00654b3e4c75374280a5b3c6e2f094aae65b8ca23a15d84eb3c1c1810aa"
	for _, in := range []string{
		"sha256:" + hexBody,
		hexBody,
		"SHA256:" + strings.ToUpper(hexBody),
		"ghcr.io/org/app:v1@sha256:" + hexBody,
		"  sha256:" + hexBody + "  ",
	} {
		got, err := CanonicalDigest(in)
		if err != nil {
			t.Errorf("CanonicalDigest(%q): %v", in, err)
			continue
		}
		if got != "sha256:"+hexBody {
			t.Errorf("CanonicalDigest(%q) = %q", in, got)
		}
	}
}

// A tag names no content, so it cannot name what was measured.
func TestCanonicalDigestRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"ghcr.io/org/app:v1",
		"sha256:abcd",
		"sha512:" + strings.Repeat("a", 128),
		"sha256:" + strings.Repeat("g", 64),
	} {
		if got, err := CanonicalDigest(in); err == nil {
			t.Errorf("CanonicalDigest(%q) = %q, want error", in, got)
		}
	}
}
