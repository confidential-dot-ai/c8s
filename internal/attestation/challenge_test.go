package attestation

import (
	"testing"
	"time"
)

func TestCreateReturns32Bytes(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()
	if got := len(challenge[:]); got != 32 {
		t.Fatalf("expected 32 bytes, got %d", got)
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

// TestCreateEvictsExpiredChallenges backdates a stored challenge past the TTL
// and checks the next Create removes it, so the map cannot grow unbounded.
func TestCreateEvictsExpiredChallenges(t *testing.T) {
	store := NewChallengeStore(time.Hour)
	old := store.Create()
	store.mu.Lock()
	store.challenges[old] = time.Now().Add(-2 * time.Hour)
	store.mu.Unlock()

	fresh := store.Create()

	store.mu.Lock()
	_, oldKept := store.challenges[old]
	_, freshKept := store.challenges[fresh]
	n := len(store.challenges)
	store.mu.Unlock()

	if oldKept {
		t.Error("expired challenge was not evicted by Create")
	}
	if !freshKept {
		t.Error("fresh challenge missing after Create")
	}
	if n != 1 {
		t.Errorf("store holds %d challenges, want 1", n)
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
