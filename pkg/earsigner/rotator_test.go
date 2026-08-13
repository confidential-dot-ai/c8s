package earsigner_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestGenerate(t *testing.T) {
	pem1, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(pem1) == 0 {
		t.Fatal("Generate returned empty PEM")
	}
	// Generated PEM must be parseable by NewRotator.
	if _, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: time.Hour,
		Overlap:  time.Minute,
		Logger:   discardLogger(),
	}, pem1, func(*ecdsa.PrivateKey, string) {}); err != nil {
		t.Fatalf("NewRotator with generated key: %v", err)
	}

	// Two calls must produce distinct keys.
	pem2, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate (2): %v", err)
	}
	if string(pem1) == string(pem2) {
		t.Error("Generate produced identical keys on two calls")
	}
}

func TestNewRotator_InvalidPEM(t *testing.T) {
	cases := map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not a pem at all"),
		"bad-block": []byte("-----BEGIN EC PRIVATE KEY-----\nQUJD\n-----END EC PRIVATE KEY-----\n"),
	}
	for name, pem := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := earsigner.NewRotator(earsigner.RotatorConfig{
				Interval: time.Hour,
				Logger:   discardLogger(),
			}, pem, func(*ecdsa.PrivateKey, string) {})
			if err == nil {
				t.Fatal("expected error for invalid PEM, got nil")
			}
			if r != nil {
				t.Error("expected nil rotator on error")
			}
		})
	}
}

func TestPublicKey_ActiveMatch(t *testing.T) {
	r, _ := newTestRotator(t)

	// The kid for the active key is whatever appears in the JWKS.
	kid := firstKid(t, r)
	pub, err := r.PublicKey(kid)
	if err != nil {
		t.Fatalf("PublicKey(active kid): %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey returned nil public key")
	}
}

func TestJWKSetJSON_HasActiveKey(t *testing.T) {
	r, _ := newTestRotator(t)

	body := r.JWKSetJSON()
	keys := parseJWKS(t, body)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in fresh JWKS, got %d", len(keys))
	}
	if keys[0].Kid == "" {
		t.Error("active key has empty kid")
	}
	if keys[0].Crv != "P-256" {
		t.Errorf("crv = %q, want P-256", keys[0].Crv)
	}
}

// TestRun_Rotation drives the rotation loop with a tiny interval to exercise
// rotate(), the swap callback, and JWKS serving of a retiring key.
func TestRun_Rotation(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var (
		mu          sync.Mutex
		swappedKids []string
	)
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: 5 * time.Millisecond,
		Overlap:  time.Hour, // keep retiring keys alive so JWKS grows
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(_ *ecdsa.PrivateKey, kid string) {
		mu.Lock()
		swappedKids = append(swappedKids, kid)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}

	initialKid := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	// Wait for at least one rotation by polling the swap callback.
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(swappedKids)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for rotation")
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	mu.Lock()
	defer mu.Unlock()
	newKid := swappedKids[0]
	if newKid == initialKid {
		t.Error("rotation produced the same kid as the initial key")
	}

	// New active kid must be resolvable.
	if _, err := r.PublicKey(newKid); err != nil {
		t.Errorf("PublicKey(new active kid): %v", err)
	}
	// The original key should still resolve while in the overlap window.
	if _, err := r.PublicKey(initialKid); err != nil {
		t.Errorf("PublicKey(retiring kid): %v", err)
	}

	// JWKS must now contain at least the active + one retiring key.
	keys := parseJWKS(t, r.JWKSetJSON())
	if len(keys) < 2 {
		t.Errorf("expected >=2 keys in JWKS after rotation, got %d", len(keys))
	}
}

// TestPublicKey_RetiringKeyExpires proves that a retiring key is rejected once
// it passes its overlap deadline, even if a later rotation has not yet evicted
// it from the retiring set. Without the lookup-time deadline check a retired
// (possibly compromised) key would keep verifying tokens until the next
// rotation — with defaults ~720h, far beyond the ~25h overlap policy.
func TestPublicKey_RetiringKeyExpires(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	swapped := make(chan struct{}, 1)
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: 200 * time.Millisecond,
		Overlap:  10 * time.Millisecond,
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(_ *ecdsa.PrivateKey, _ string) {
		select {
		case swapped <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	initialKid := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Wait for the first rotation (which retires the initial key), then stop the
	// loop so no subsequent rotation can evict it — isolating the lookup-time
	// deadline check from eviction.
	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first rotation")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// The initial key was retired with a 10ms overlap; wait well past it.
	time.Sleep(100 * time.Millisecond)

	if _, err := r.PublicKey(initialKid); err == nil {
		t.Error("PublicKey accepted a retiring key past its overlap deadline")
	}
}

// TestJWKSDropsRetiredKeyPastOverlap proves the served JWKS drops a retiring
// key once its overlap deadline passes, matching the lookup-time rejection in
// PublicKey. The loop is stopped right after the first rotation so no later
// rotate() can mask a stale served set.
func TestJWKSDropsRetiredKeyPastOverlap(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	swapped := make(chan struct{}, 1)
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: 100 * time.Millisecond,
		Overlap:  400 * time.Millisecond,
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(_ *ecdsa.PrivateKey, _ string) {
		select {
		case swapped <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	initialKid := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first rotation")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// Inside the overlap window both views serve the retiring key.
	if _, err := r.PublicKey(initialKid); err != nil {
		t.Fatalf("PublicKey(retiring kid) inside overlap: %v", err)
	}
	if !jwksHasKid(parseJWKS(t, r.JWKSetJSON()), initialKid) {
		t.Fatal("JWKS missing retiring key inside its overlap window")
	}

	// Past the overlap deadline, with no further rotation, both views must
	// drop it.
	time.Sleep(600 * time.Millisecond)

	if _, err := r.PublicKey(initialKid); err == nil {
		t.Error("PublicKey accepted a key past its overlap deadline")
	}
	if jwksHasKid(parseJWKS(t, r.JWKSetJSON()), initialKid) {
		t.Error("JWKS still publishes a key past its overlap deadline")
	}
}

// TestJWKSAgreesWithPublicKeyAcrossSchedule walks the rotation schedule —
// initial, post-rotate inside overlap, past overlap expiry, next rotate — and
// asserts PublicKey and the served JWKS agree on every key at every point.
func TestJWKSAgreesWithPublicKeyAcrossSchedule(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	const (
		interval = 600 * time.Millisecond
		overlap  = 250 * time.Millisecond
	)
	swaps := make(chan string, 4)
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: interval,
		Overlap:  overlap,
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(_ *ecdsa.PrivateKey, kid string) { swaps <- kid })
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	k0 := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}()

	assertAgree := func(kid string, wantServed bool, when string) {
		t.Helper()
		_, pubErr := r.PublicKey(kid)
		inJWKS := jwksHasKid(parseJWKS(t, r.JWKSetJSON()), kid)
		if wantServed {
			if pubErr != nil {
				t.Errorf("%s: PublicKey(%q): %v", when, kid, pubErr)
			}
			if !inJWKS {
				t.Errorf("%s: JWKS does not publish %q", when, kid)
			}
			return
		}
		if pubErr == nil {
			t.Errorf("%s: PublicKey accepted retired key %q", when, kid)
		}
		if inJWKS {
			t.Errorf("%s: JWKS publishes retired key %q", when, kid)
		}
	}
	nextSwap := func() string {
		t.Helper()
		select {
		case kid := <-swaps:
			return kid
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for rotation")
			return ""
		}
	}

	// Initial: k0 active.
	assertAgree(k0, true, "initial")

	// First rotation: k0 retiring inside its overlap window, k1 active.
	k1 := nextSwap()
	assertAgree(k0, true, "inside overlap")
	assertAgree(k1, true, "inside overlap")

	// Past k0's overlap deadline but before the next rotation.
	time.Sleep(overlap + 150*time.Millisecond)
	assertAgree(k0, false, "past overlap")
	assertAgree(k1, true, "past overlap")

	// Second rotation: k0 evicted, k1 retiring inside overlap, k2 active.
	k2 := nextSwap()
	assertAgree(k0, false, "after next rotate")
	assertAgree(k1, true, "after next rotate")
	assertAgree(k2, true, "after next rotate")
}

// TestJWKSetJSONConcurrentWithRotation hammers JWKSetJSON and PublicKey from
// concurrent readers while the rotation loop runs, asserting every served
// body is a complete valid JWKS and lookups stay correct mid-rotation.
func TestJWKSetJSONConcurrentWithRotation(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Overlap is long compared to the reader run time, so the initial key
	// must resolve via PublicKey throughout.
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: 5 * time.Millisecond,
		Overlap:  time.Second,
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(*ecdsa.PrivateKey, string) {})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	initialKid := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	const readers = 8
	errs := make(chan error, readers)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				var set struct {
					Keys []jwkEntry `json:"keys"`
				}
				if err := json.Unmarshal(r.JWKSetJSON(), &set); err != nil {
					errs <- fmt.Errorf("unmarshal served JWKS: %w", err)
					return
				}
				if len(set.Keys) == 0 {
					errs <- errors.New("served JWKS has no keys")
					return
				}
				for _, k := range set.Keys {
					if k.Kid == "" || k.Kty == "" || k.Crv == "" {
						errs <- fmt.Errorf("served incomplete JWK entry: %+v", k)
						return
					}
				}
				if _, err := r.PublicKey(initialKid); err != nil {
					errs <- fmt.Errorf("PublicKey(retiring kid) mid-rotation: %w", err)
					return
				}
				if _, err := r.PublicKey("never-issued"); err == nil {
					errs <- errors.New("PublicKey resolved an unknown kid")
					return
				}
			}
		}()
	}
	wg.Wait()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
}

// firstTickIn starts Run with an already-cancelled context so it exits right
// after logging, and returns the first_tick_in duration from the startup log
// record (the only observable form of the computed first tick).
func firstTickIn(t *testing.T, keyPEM []byte, cfg earsigner.RotatorConfig) time.Duration {
	t.Helper()
	var buf bytes.Buffer
	cfg.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	r, err := earsigner.NewRotator(cfg, keyPEM, func(*ecdsa.PrivateKey, string) {})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Run(ctx)

	dec := json.NewDecoder(&buf)
	for {
		var rec struct {
			Msg         string `json:"msg"`
			FirstTickIn int64  `json:"first_tick_in"`
		}
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("no startup log record found: %v", err)
		}
		if rec.Msg == "rotation loop starting" {
			return time.Duration(rec.FirstTickIn)
		}
	}
}

func TestRunFirstTickWithoutJitter(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got := firstTickIn(t, keyPEM, earsigner.RotatorConfig{
		Interval: time.Hour,
		Overlap:  time.Minute,
		Jitter:   0,
	})
	if got != time.Hour {
		t.Fatalf("first tick = %v, want exactly the interval with zero jitter", got)
	}
}

// TestRunFirstTickJitterBounds pins the jitter window: with Jitter=0.5 the
// first tick lands in [Interval, Interval*1.5). Sampled repeatedly because
// the jitter fraction is random.
func TestRunFirstTickJitterBounds(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const interval = time.Hour
	for i := 0; i < 60; i++ {
		got := firstTickIn(t, keyPEM, earsigner.RotatorConfig{
			Interval: interval,
			Overlap:  time.Minute,
			Jitter:   0.5,
		})
		if got < interval || got >= interval+interval/2 {
			t.Fatalf("first tick = %v, want in [%v, %v)", got, interval, interval+interval/2)
		}
	}
}

// --- helpers ---

type jwkEntry struct {
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	Kty string `json:"kty"`
}

func parseJWKS(t *testing.T, body []byte) []jwkEntry {
	t.Helper()
	var set struct {
		Keys []jwkEntry `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal JWKS %q: %v", body, err)
	}
	return set.Keys
}

func jwksHasKid(keys []jwkEntry, kid string) bool {
	for _, k := range keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

func firstKid(t *testing.T, r *earsigner.Rotator) string {
	t.Helper()
	keys := parseJWKS(t, r.JWKSetJSON())
	if len(keys) == 0 {
		t.Fatal("JWKS has no keys")
	}
	return keys[0].Kid
}
