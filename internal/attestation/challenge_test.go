package attestation

import (
	"testing"
	"time"
)

func TestCreateReturns32Bytes(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()
	if len(challenge) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(challenge))
	}
}

func TestConsumeValidChallenge(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()

	if !store.Consume(challenge[:]) {
		t.Fatal("expected Consume to return true for valid challenge")
	}
}

func TestConsumeUnknownChallenge(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)

	unknown := [32]byte{0xff}
	if store.Consume(unknown[:]) {
		t.Fatal("expected Consume to return false for unknown challenge")
	}
}

func TestConsumeReusedChallenge(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()

	if !store.Consume(challenge[:]) {
		t.Fatal("first consume should succeed")
	}
	if store.Consume(challenge[:]) {
		t.Fatal("second consume should fail (single use)")
	}
}

func TestConsumeExpiredChallenge(t *testing.T) {
	store := NewChallengeStore(1 * time.Millisecond)
	challenge := store.Create()

	time.Sleep(10 * time.Millisecond)

	if store.Consume(challenge[:]) {
		t.Fatal("expected Consume to return false for expired challenge")
	}
}
