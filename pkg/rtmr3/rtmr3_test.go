package rtmr3

import (
	"crypto/sha512"
	"encoding/hex"
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

// TestForOperatorKeyFormula checks the two-step formula
// RTMR[3] = SHA384(0x00*48 || SHA384(pubkey)) against an independent compute.
func TestForOperatorKeyFormula(t *testing.T) {
	pub := []byte("some operator public key bytes")
	got := ForOperatorKey(pub)

	keyDigest := sha512.Sum384(pub)
	want := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	if got != want {
		t.Errorf("ForOperatorKey = %x, want %x", got, want)
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
