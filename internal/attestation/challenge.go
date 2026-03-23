package attestation

import (
	"crypto/rand"
	"sync"
	"time"
)

// ChallengeStore holds short-lived attestation challenges. Each challenge can
// only be consumed once, preventing replay attacks.
//
// NOTE: challenges are stored in-memory and lost on restart. This is acceptable
// for single-instance deployments but must be addressed for HA configurations.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[[32]byte]time.Time
	ttl        time.Duration
}

// NewChallengeStore creates a new challenge store with the given TTL.
func NewChallengeStore(ttl time.Duration) ChallengeStore {
	return ChallengeStore{
		challenges: make(map[[32]byte]time.Time),
		ttl:        ttl,
	}
}

// Create generates a new 32-byte random challenge and stores it.
func (s *ChallengeStore) Create() [32]byte {
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Evict expired challenges while holding the lock
	for k, created := range s.challenges {
		if now.Sub(created) >= s.ttl {
			delete(s.challenges, k)
		}
	}

	s.challenges[challenge] = now
	return challenge
}

// Consume removes and validates a challenge, returning true if it was valid
// and not expired. The challenge is removed regardless so it cannot be reused.
func (s *ChallengeStore) Consume(challenge []byte) bool {
	if len(challenge) != 32 {
		return false
	}

	var key [32]byte
	copy(key[:], challenge)

	s.mu.Lock()
	defer s.mu.Unlock()

	created, ok := s.challenges[key]
	if !ok {
		return false
	}
	delete(s.challenges, key)

	return time.Since(created) < s.ttl
}
