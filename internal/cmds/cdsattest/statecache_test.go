package cdsattest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
)

// The policy digests the tests move between: P is the source, Q the target.
var (
	digestP = "sha256:" + hexRepeat(0xaa)
	digestQ = "sha256:" + hexRepeat(0xbb)
)

// testState builds a valid statement with no update outstanding, so a test can
// say "position 7 under this authority" without restating the whole shape.
func testState(t *testing.T, authority ed25519.PublicKey, position uint64) policystate.State {
	t.Helper()
	fingerprint, err := policystate.AuthorityFingerprint(authority)
	if err != nil {
		t.Fatal(err)
	}
	return policystate.State{
		Protocol:      policystate.Protocol,
		DeploymentID:  "c8s-test",
		Authority:     fingerprint,
		LogHead:       "sha256:" + hexRepeat(byte(position)),
		LogPosition:   position,
		ActiveVersion: 1,
		ActiveDigest:  digestP,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

func hexRepeat(b byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i := 0; i < 64; i += 2 {
		out[i], out[i+1] = digits[b>>4], digits[b&0x0f]
	}
	return string(out)
}

func mustSignState(t *testing.T, priv ed25519.PrivateKey, s policystate.State) policystate.SignedState {
	t.Helper()
	signed, err := policystate.SignState(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func mustGenerateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stateServer serves GET /.well-known/c8s/state from a statement the test
// sets, which is all the cache reads.
type stateServer struct {
	mu     sync.Mutex
	signed policystate.SignedState
	status int
}

func (s *stateServer) set(signed policystate.SignedState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signed = signed
}

func (s *stateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	signed, status := s.signed, s.status
	s.mu.Unlock()
	if r.URL.Path != policystate.PathState {
		http.NotFound(w, r)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signed)
}

func newTestStateCache(t *testing.T, srv *stateServer) *stateCache {
	t.Helper()
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return newStateCache(policystateclient.New(ts.URL), time.Hour, quietLogger())
}

func TestStateCacheKeepsOnlyVerifiedStatements(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	srv := &stateServer{}
	cache := newTestStateCache(t, srv)
	ctx := context.Background()

	good := mustSignState(t, priv, testState(t, pub, 3))
	srv.set(good)
	cache.refreshOnce(ctx)
	held, _, ok := cache.State()
	if !ok || held.Statement.LogPosition != 3 {
		t.Fatalf("State() = %+v, %v, want the statement at position 3", held.Statement, ok)
	}

	// A statement whose signature does not cover the statement it arrives
	// with never replaces the one held.
	forged := good
	forged.Signature = mustSignState(t, priv, testState(t, pub, 4)).Signature
	srv.set(forged)
	cache.refreshOnce(ctx)
	held, _, _ = cache.State()
	if held.Statement.LogPosition != 3 {
		t.Fatalf("a statement that did not verify replaced the held one: position %d", held.Statement.LogPosition)
	}
}

func TestStateCacheRefusesALogRewind(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	srv := &stateServer{}
	cache := newTestStateCache(t, srv)
	ctx := context.Background()

	srv.set(mustSignState(t, priv, testState(t, pub, 9)))
	cache.refreshOnce(ctx)
	srv.set(mustSignState(t, priv, testState(t, pub, 8)))
	cache.refreshOnce(ctx)
	held, _, _ := cache.State()
	if held.Statement.LogPosition != 9 {
		t.Fatalf("held log position = %d, want 9: a rewind under the same authority must be refused", held.Statement.LogPosition)
	}
}

// A restarted CDS signs with a new key. Its statements verify under the key
// they carry, so the cache follows the new authority rather than holding a
// statement no live CDS still signs.
func TestStateCacheFollowsANewAuthority(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	srv := &stateServer{}
	cache := newTestStateCache(t, srv)
	ctx := context.Background()

	srv.set(mustSignState(t, priv, testState(t, pub, 9)))
	cache.refreshOnce(ctx)

	restarted, restartedPriv := mustGenerateKey(t)
	srv.set(mustSignState(t, restartedPriv, testState(t, restarted, 1)))
	cache.refreshOnce(ctx)

	held, _, _ := cache.State()
	fingerprint, err := policystate.AuthorityFingerprint(restarted)
	if err != nil {
		t.Fatal(err)
	}
	if held.Statement.Authority != fingerprint {
		t.Fatalf("held authority = %s, want the restarted CDS's %s", held.Statement.Authority, fingerprint)
	}
}

func TestStateCacheCallsTheDriverOnEveryAcceptedStatement(t *testing.T) {
	pub, priv := mustGenerateKey(t)
	srv := &stateServer{}
	cache := newTestStateCache(t, srv)
	var seen []uint64
	cache.follow(func(_ context.Context, s policystate.State) { seen = append(seen, s.LogPosition) })
	ctx := context.Background()

	srv.set(mustSignState(t, priv, testState(t, pub, 1)))
	cache.refreshOnce(ctx)
	srv.set(mustSignState(t, priv, testState(t, pub, 2)))
	cache.refreshOnce(ctx)
	// Refused: the driver must not see a rewind.
	srv.set(mustSignState(t, priv, testState(t, pub, 1)))
	cache.refreshOnce(ctx)

	if want := []uint64{1, 2}; len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("driver saw positions %v, want %v", seen, want)
	}
}
