// Package earsigner manages the EAR token-signing key lifecycle with
// overlap-based rotation and JWKS serving.
package earsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/jwks"
)

const maxSnapshotKeys = 32

// Snapshot is the protected EAR signer state for a CDS handoff. PrivateKeyPEM
// is transferred only inside the recipient-bound handoff ciphertext.
type Snapshot struct {
	Active       SnapshotKey   `json:"active"`
	Retiring     []SnapshotKey `json:"retiring,omitempty"`
	NextRotation time.Time     `json:"next_rotation"`
}

// SnapshotKey is one EAR signing key and its overlap deadline.
type SnapshotKey struct {
	KID           string    `json:"kid"`
	PrivateKeyPEM string    `json:"private_key_pem"`
	NotAfter      time.Time `json:"not_after"`
}

// RotatorConfig configures the key rotation loop.
type RotatorConfig struct {
	Interval time.Duration // rotation interval (default 720h)
	Overlap  time.Duration // how long retiring keys stay in JWKS (default 25h)
	Jitter   float64       // fraction of Interval to jitter first tick (default 0.1)
	Logger   *slog.Logger
}

// managedKey is a key with lifecycle metadata.
type managedKey struct {
	kid       string
	key       *ecdsa.PrivateKey
	notAfterT time.Time
}

// expired reports whether now is at or past the key's deadline.
func (k *managedKey) expired(now time.Time) bool {
	return !now.Before(k.notAfterT)
}

// SwapKeyFunc is called when the active signing key changes.
type SwapKeyFunc func(key *ecdsa.PrivateKey, kid string)

// Rotator manages the token-signer key lifecycle with overlap-based
// rotation. Keys are ephemeral and live only in memory.
type Rotator struct {
	cfg     RotatorConfig
	swapKey SwapKeyFunc

	mu           sync.RWMutex
	active       *managedKey
	retiring     []*managedKey
	nextRotation time.Time
	frozen       bool
	resume       chan struct{}
	// beforeRotateLock is a test seam for the timer-wake/freeze race.
	beforeRotateLock func()
}

// Generate creates a fresh P-256 private key and returns it as PEM bytes.
func Generate() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	return certutil.MarshalECKeyPEM(key)
}

// NewRotator creates a rotator from an initial key PEM.
func NewRotator(cfg RotatorConfig, initialKeyPEM []byte, swapKey SwapKeyFunc) (*Rotator, error) {
	key, err := certutil.ParseECPrivateKey(initialKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse initial key: %w", err)
	}
	kid, err := jwks.Thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	r := &Rotator{
		cfg:     cfg,
		swapKey: swapKey,
		active: &managedKey{
			kid:       kid,
			key:       key,
			notAfterT: now.Add(cfg.Interval + cfg.Overlap),
		},
	}
	return r, nil
}

// NewRotatorFromSnapshot restores the active and overlap EAR signer keys.
func NewRotatorFromSnapshot(cfg RotatorConfig, snapshot Snapshot, swapKey SwapKeyFunc) (*Rotator, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	if cfg.Interval > 0 && snapshot.NextRotation.IsZero() {
		return nil, fmt.Errorf("EAR signer snapshot has no next rotation time")
	}
	active, err := managedKeyFromSnapshot(snapshot.Active)
	if err != nil {
		return nil, err
	}
	retiring := make([]*managedKey, 0, len(snapshot.Retiring))
	for _, item := range snapshot.Retiring {
		key, err := managedKeyFromSnapshot(item)
		if err != nil {
			return nil, err
		}
		retiring = append(retiring, key)
	}
	return &Rotator{cfg: cfg, swapKey: swapKey, active: active, retiring: retiring, nextRotation: snapshot.NextRotation}, nil
}

func managedKeyFromSnapshot(item SnapshotKey) (*managedKey, error) {
	key, err := certutil.ParseECPrivateKey([]byte(item.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse EAR signer snapshot key: %w", err)
	}
	kid, err := jwks.Thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if kid != item.KID {
		return nil, fmt.Errorf("EAR signer snapshot kid does not match its key")
	}
	return &managedKey{kid: kid, key: key, notAfterT: item.NotAfter}, nil
}

// ValidateSnapshot validates size, keys, key identities, and overlap bounds.
func ValidateSnapshot(snapshot Snapshot) error {
	if snapshot.Active.KID == "" || snapshot.Active.PrivateKeyPEM == "" {
		return fmt.Errorf("EAR signer snapshot has no active key")
	}
	if len(snapshot.Retiring) > maxSnapshotKeys-1 {
		return fmt.Errorf("EAR signer snapshot has too many retiring keys")
	}
	seen := make(map[string]struct{}, len(snapshot.Retiring)+1)
	for _, item := range append([]SnapshotKey{snapshot.Active}, snapshot.Retiring...) {
		key, err := managedKeyFromSnapshot(item)
		if err != nil {
			return err
		}
		if key.key.Curve != elliptic.P256() {
			return fmt.Errorf("EAR signer snapshot key must use P-256")
		}
		if _, ok := seen[item.KID]; ok {
			return fmt.Errorf("EAR signer snapshot contains a duplicate kid")
		}
		seen[item.KID] = struct{}{}
	}
	return nil
}

// Snapshot returns an immutable copy of the active and live overlap keys.
func (r *Rotator) Snapshot() (Snapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshotLocked()
}

// Freeze stops rotation and returns one atomic signer snapshot.
func (r *Rotator) Freeze() (Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nextRotation.IsZero() && r.cfg.Interval > 0 {
		jitter := time.Duration(float64(r.cfg.Interval) * r.cfg.Jitter * mathrand.Float64())
		r.nextRotation = time.Now().Add(r.cfg.Interval + jitter)
	}
	if !r.frozen {
		r.frozen = true
		r.resume = make(chan struct{})
	}
	return r.snapshotLocked()
}

// Resume lets rotation continue after an aborted pre-activation transfer.
func (r *Rotator) Resume() {
	r.mu.Lock()
	if r.frozen {
		r.frozen = false
		close(r.resume)
		r.resume = nil
	}
	r.mu.Unlock()
}

func (r *Rotator) snapshotLocked() (Snapshot, error) {
	if r.active == nil {
		return Snapshot{}, fmt.Errorf("EAR signer has no active key")
	}
	toSnapshot := func(key *managedKey) (SnapshotKey, error) {
		pemBytes, err := certutil.MarshalECKeyPEM(key.key)
		if err != nil {
			return SnapshotKey{}, err
		}
		return SnapshotKey{KID: key.kid, PrivateKeyPEM: string(pemBytes), NotAfter: key.notAfterT}, nil
	}
	active, err := toSnapshot(r.active)
	if err != nil {
		return Snapshot{}, err
	}
	now := time.Now()
	retiring := make([]SnapshotKey, 0, len(r.retiring))
	for _, key := range r.retiring {
		if key.expired(now) {
			continue
		}
		item, err := toSnapshot(key)
		if err != nil {
			return Snapshot{}, err
		}
		retiring = append(retiring, item)
	}
	return Snapshot{Active: active, Retiring: retiring, NextRotation: r.nextRotation}, nil
}

// JWKSetJSON serialises the current key set for the JWKS endpoint: the
// active key plus retiring keys within their overlap window.
func (r *Rotator) JWKSetJSON() []byte {
	r.mu.RLock()
	var keys []jose.JSONWebKey
	if r.active != nil {
		if jwk, err := jwks.FromPublicKey(&r.active.key.PublicKey); err == nil {
			keys = append(keys, jwk)
		}
	}
	// Retiring keys are served until their overlap deadline, as in PublicKey.
	now := time.Now()
	for _, k := range r.retiring {
		if k.expired(now) {
			continue
		}
		if jwk, err := jwks.FromPublicKey(&k.key.PublicKey); err == nil {
			keys = append(keys, jwk)
		}
	}
	r.mu.RUnlock()

	body, err := jwks.MarshalSet(keys...)
	if err != nil {
		r.cfg.Logger.Error("failed to marshal JWKS", "error", err)
		return []byte(`{"keys":[]}`)
	}
	return body
}

// PublicKey returns the ECDSA public key matching kid from the active or
// retiring set. A kid is always required: with an overlap window the active
// and retiring keys coexist, and routing every kid-less token to "active"
// would silently mis-verify tokens signed by a retiring key. Satisfies the
// issuer.KeyProvider interface so callers can verify EAR JWTs against the
// rotator's in-memory key state without an out-of-process JWKS fetch.
func (r *Rotator) PublicKey(kid string) (*ecdsa.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("token-signer lookup requires a kid header")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active != nil && r.active.kid == kid {
		return &r.active.key.PublicKey, nil
	}
	// A retiring key is only trusted until its overlap deadline. Eviction from
	// r.retiring happens on the next rotate(), which with default settings is
	// ~720h away while the overlap is ~25h — so without this deadline check a
	// retired (possibly compromised) key would keep verifying tokens for weeks
	// past its configured retirement. Reject it at lookup time instead.
	now := time.Now()
	for _, k := range r.retiring {
		if k.kid == kid {
			if k.expired(now) {
				return nil, fmt.Errorf("token-signer key for kid %q is retired (past overlap deadline)", kid)
			}
			return &k.key.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("no token-signer key for kid %q", kid)
}

// Run starts the rotation loop. Blocks until ctx is cancelled.
func (r *Rotator) Run(ctx context.Context) {
	// Jitter the first tick to avoid thundering-herd after fleet restarts.
	r.mu.Lock()
	var first time.Duration
	if r.nextRotation.IsZero() {
		jitter := time.Duration(float64(r.cfg.Interval) * r.cfg.Jitter * mathrand.Float64())
		first = r.cfg.Interval + jitter
		r.nextRotation = time.Now().Add(first)
	} else {
		first = time.Until(r.nextRotation)
		if first < 0 {
			first = 0
		}
	}
	r.mu.Unlock()
	r.cfg.Logger.Info("rotation loop starting", "interval", r.cfg.Interval, "first_tick_in", first)

	timer := time.NewTimer(first)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.mu.RLock()
			frozen, resume := r.frozen, r.resume
			r.mu.RUnlock()
			if frozen {
				select {
				case <-ctx.Done():
					return
				case <-resume:
					timer.Reset(0)
					continue
				}
			}
			r.rotate()
			timer.Reset(r.cfg.Interval)
		}
	}
}

func (r *Rotator) rotate() {
	r.cfg.Logger.Info("rotating token-signer key")

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		r.cfg.Logger.Error("key generation failed", "error", err)
		return
	}
	newKid, err := jwks.Thumbprint(&newKey.PublicKey)
	if err != nil {
		r.cfg.Logger.Error("thumbprint failed", "error", err)
		return
	}

	if r.beforeRotateLock != nil {
		r.beforeRotateLock()
	}
	r.mu.Lock()
	// Freeze and rotation use this same write lock. Thus a snapshot cannot
	// finish before a timer-woken rotation mutates the signer state.
	if r.frozen {
		r.mu.Unlock()
		return
	}
	now := time.Now()
	if old := r.active; old != nil {
		old.notAfterT = now.Add(r.cfg.Overlap)
		r.retiring = append(r.retiring, old)
	}

	r.active = &managedKey{
		kid:       newKid,
		key:       newKey,
		notAfterT: now.Add(r.cfg.Interval + r.cfg.Overlap),
	}
	r.nextRotation = now.Add(r.cfg.Interval)

	// Evict expired retiring keys.
	live := r.retiring[:0]
	for _, k := range r.retiring {
		if !k.expired(now) {
			live = append(live, k)
		} else {
			r.cfg.Logger.Info("evicted expired key", "kid", k.kid)
		}
	}
	// clear the obsolete elements to enable GC
	clear(r.retiring[len(live):])
	r.retiring = live
	r.mu.Unlock()

	// Swap the signing key in the Issuer.
	r.swapKey(newKey, newKid)

	r.cfg.Logger.Info("rotation complete", "new_kid", newKid, "retiring_keys", len(r.retiring))
}
