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

// A fixed PKIX public-key PEM in the exact shape `openssl ec -pubout` emits,
// trailing newline included — the byte layout the initrd hashes.
const testOperatorPubPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtO+wEJtA/q+o7spl3iXUdzT9pLY/
Ln7t8a7OvDkCwGUhGYtOC2MGQ08BTMRqi2Q306MP5Xh9TnKAf0I/5QOglA==
-----END PUBLIC KEY-----
`

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
		// The ForOperatorKey vector is hardware-confirmed: RTMR[3] as read back
		// from a TDX CVM launched with exactly this P-256 pubkey file.
		{"ForOperatorKey(testPEM)", ForOperatorKey([]byte(testOperatorPubPEM)),
			"a9b91d920971de864899fb5925c4b5230bf88750dd59866d8d34aeb975e86761ea7488ade961908d9595b6202c9e6470"},
		{"FromDigestsSeeded(ForOperatorKey(testPEM),[A,B])",
			FromDigestsSeeded(ForOperatorKey([]byte(testOperatorPubPEM)), []string{digestA, digestB}),
			"ed90ff0e91dd3dd4304808ca32436d0cd6db768381ca0c7e20b1ff375b3e15d8515f3ca97009d73a253a4266386c6a14"},
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

// ForOperatorKey must be exactly one extend of the key's SHA-384, so a
// verifier can chain per-workload extends onto it.
func TestForOperatorKeyIsSingleExtendOfKeyDigest(t *testing.T) {
	pub := []byte("-----BEGIN PUBLIC KEY-----\nnot a real key\n-----END PUBLIC KEY-----\n")
	if ForOperatorKey(pub) != Extend(Zero, sha512.Sum384(pub)) {
		t.Error("ForOperatorKey must equal Extend(Zero, SHA384(pubkey))")
	}
}

// The seed is over the EXACT bytes supplied: a re-wrapped or newline-stripped
// PEM is a different key as far as the register is concerned. Pinning that
// here makes the footgun a deliberate choice rather than a surprise.
func TestForOperatorKeyIsByteExact(t *testing.T) {
	withNewline := []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
	withoutNewline := withNewline[:len(withNewline)-1]
	if ForOperatorKey(withNewline) == ForOperatorKey(withoutNewline) {
		t.Error("ForOperatorKey must not normalize its input; a trailing newline changes the seed")
	}
}

// TestForOperatorKeyMatchesHardware pins the operator-key extend to the exact
// value a B1+B2 hardware run produced: keyDigest is SHA-384(operator pubkey)
// from that run, wantRTMR3 what /sys/.../rtmr3:sha384 read back after launch.
func TestForOperatorKeyMatchesHardware(t *testing.T) {
	const (
		keyDigest = "0c06aa4f364e480ece13c58b1585dab43d7222fa331ccc9ff05ea18fdd39a4d9d75e87d711ac6aeda2782c2e339de7c1"
		wantRTMR3 = "db479dfe6333f8d3a2761494b6004bc4332688c6d5b72577b48ecfc0409e4cb53988dcd26b89ec605a81b00e7f0e0863"
	)
	dig, err := hex.DecodeString(keyDigest)
	if err != nil {
		t.Fatal(err)
	}
	// ForOperatorKey hashes the pubkey; here we already have the digest, so
	// pin the second step (the Zero extend) directly.
	got := Extend(Zero, [Size]byte(dig))
	if hex.EncodeToString(got[:]) != wantRTMR3 {
		t.Errorf("RTMR[3] from key digest = %x, want %s (hardware-confirmed)", got, wantRTMR3)
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

func TestCanonicalDigest(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		ref  string
		want string // "" = must be rejected
	}{
		{"bare canonical digest", "sha256:" + hex64, "sha256:" + hex64},
		{"digest-pinned ref", "ghcr.io/acme/api@sha256:" + hex64, "sha256:" + hex64},
		{"digest-pinned ref with ignored tag", "ghcr.io/acme/api:v1@sha256:" + hex64, "sha256:" + hex64},
		{"tag ref", "ghcr.io/acme/api:v1", ""},
		{"floating tag", "nginx:latest", ""},
		{"bare name", "nginx", ""},
		{"uppercase hex", "sha256:" + strings.ToUpper(hex64), ""},
		{"mixed-case hex in ref", "acme/api@sha256:AB" + strings.Repeat("ab", 31), ""},
		{"too short", "sha256:" + hex64[:62], ""},
		{"too long", "sha256:" + hex64 + "ab", ""},
		{"wrong algorithm", "sha512:" + strings.Repeat("ab", 64), ""},
		{"wrong algorithm in ref", "acme/api@sha512:" + strings.Repeat("ab", 64), ""},
		{"empty name before @", "@sha256:" + hex64, ""},
		{"non-hex chars", "sha256:" + strings.Repeat("zz", 32), ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalDigest(tc.ref)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("CanonicalDigest(%q) = %q, want rejection", tc.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalDigest(%q): %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalDigest(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}
