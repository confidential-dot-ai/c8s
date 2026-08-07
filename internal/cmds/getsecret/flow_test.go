package getsecret

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const flowSandbox = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// stubResolver is an inventory that vouches for one sandbox. The token route
// binds its caller by peer credentials, which a unix socket supplies; nothing
// here needs to disambiguate.
type stubResolver struct{}

func (stubResolver) SandboxForPeer(workloadclaims.Peer) (string, error) { return flowSandbox, nil }
func (stubResolver) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}

// startInventory serves the real token route on a unix socket and points the
// sidecar at it.
func startInventory(t *testing.T) {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go workloadclaims.ServeTokens(ctx, l, stubResolver{}, signer)
	t.Cleanup(func() { cancel(); l.Close() })

	sidecar.SetInventoryEndpointForTest(t, func() string { return "unix://" + sock })
}

// fakeCDS records what it was asked and answers from a scripted sequence.
type fakeCDS struct {
	mu         sync.Mutex
	challenges int
	requests   []string // "METHOD /path"
	tokens     []string // the Authorization header of each secret request
	replies    map[string][]reply
}

type reply struct {
	status int
	value  string // raw value; encoded as base64 in the response
}

func newFakeCDS(t *testing.T, replies map[string][]reply) (*fakeCDS, string) {
	t.Helper()
	f := &fakeCDS{replies: replies}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func (f *fakeCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Method == http.MethodPost && r.URL.Path == secrets.ChallengeRoute {
		f.challenges++
		nonce := make([]byte, 32)
		rand.Read(nonce)
		json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(nonce)})
		return
	}

	key := r.Method + " " + r.URL.Path
	f.requests = append(f.requests, key)
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	if r.Header.Get(secrets.ChallengeHeader) == "" {
		http.Error(w, "no challenge", http.StatusBadRequest)
		return
	}

	queue := f.replies[key]
	if len(queue) == 0 {
		http.Error(w, "unscripted", http.StatusTeapot)
		return
	}
	next := queue[0]
	f.replies[key] = queue[1:]
	if next.status != http.StatusOK && next.status != http.StatusCreated {
		w.WriteHeader(next.status)
		return
	}
	w.WriteHeader(next.status)
	json.NewEncoder(w).Encode(map[string]string{"value": base64.StdEncoding.EncodeToString([]byte(next.value))})
}

func flowConfig(t *testing.T, url string) config {
	t.Helper()
	cfg := validConfig(t)
	cfg.CDSURL = url
	return cfg
}

func testKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// An existing secret is read and returned without a create.
func TestFetchOneReadsExisting(t *testing.T) {
	startInventory(t)
	cds, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db": {{status: http.StatusOK, value: "existing"}},
	})
	got, err := fetchOne(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), "/api/db")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("value = %q, want %q", got, "existing")
	}
	if len(cds.requests) != 1 || cds.requests[0] != "GET /secrets/api/db" {
		t.Fatalf("requests = %v, want a single GET", cds.requests)
	}
}

// A path the store does not hold yet is created by the workload that finds it
// empty.
func TestFetchOneCreatesWhenAbsent(t *testing.T) {
	startInventory(t)
	cds, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db":  {{status: http.StatusNotFound}},
		"POST /secrets/api/db": {{status: http.StatusCreated, value: "minted"}},
	})
	got, err := fetchOne(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), "/api/db")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "minted" {
		t.Fatalf("value = %q, want %q", got, "minted")
	}
	if want := []string{"GET /secrets/api/db", "POST /secrets/api/db"}; !equal(cds.requests, want) {
		t.Fatalf("requests = %v, want %v", cds.requests, want)
	}
}

// The replica that loses the create race is told 409 with no value, and
// recovers by reading — otherwise it would hold nothing while its sibling holds
// the secret.
func TestFetchOneRereadsAfterLosingCreateRace(t *testing.T) {
	startInventory(t)
	cds, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db":  {{status: http.StatusNotFound}, {status: http.StatusOK, value: "winner"}},
		"POST /secrets/api/db": {{status: http.StatusConflict}},
	})
	got, err := fetchOne(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), "/api/db")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "winner" {
		t.Fatalf("value = %q, want the winning replica's value", got)
	}
	want := []string{"GET /secrets/api/db", "POST /secrets/api/db", "GET /secrets/api/db"}
	if !equal(cds.requests, want) {
		t.Fatalf("requests = %v, want %v", cds.requests, want)
	}
}

// A denial is not a create: only 404 means the path is free.
func TestFetchOneDoesNotCreateOnDenial(t *testing.T) {
	startInventory(t)
	cds, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db": {{status: http.StatusForbidden}},
	})
	if _, err := fetchOne(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), "/api/db"); err == nil {
		t.Fatal("a denial was treated as success")
	}
	for _, r := range cds.requests {
		if strings.HasPrefix(r, "POST") {
			t.Fatalf("a denial triggered a create: %v", cds.requests)
		}
	}
}

// Every request takes its own challenge and its own token: both are single-use,
// so reusing either would be refused by CDS.
func TestEveryRequestTakesAFreshChallengeAndToken(t *testing.T) {
	startInventory(t)
	cds, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db":  {{status: http.StatusNotFound}, {status: http.StatusOK, value: "v"}},
		"POST /secrets/api/db": {{status: http.StatusConflict}},
	})
	if _, err := fetchOne(context.Background(), flowConfig(t, url), http.DefaultClient, testKey(t), "/api/db"); err != nil {
		t.Fatal(err)
	}
	if cds.challenges != len(cds.requests) {
		t.Fatalf("%d challenges for %d requests, want one each", cds.challenges, len(cds.requests))
	}
	seen := map[string]bool{}
	for _, tok := range cds.tokens {
		if tok == "" || !strings.HasPrefix(tok, secrets.AuthScheme) {
			t.Fatalf("request carried no sandbox token: %q", tok)
		}
		if seen[tok] {
			t.Fatal("a sandbox token was reused across requests")
		}
		seen[tok] = true
	}
}

// Retries are the normal case — release is refused until every main container
// is running — so a denial that later clears must succeed rather than fail the
// pod.
func TestFetchWithRetryRecoversOnceReleased(t *testing.T) {
	startInventory(t)
	cds, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db": {
			{status: http.StatusForbidden},
			{status: http.StatusForbidden},
			{status: http.StatusOK, value: "released"},
		},
	})
	cfg := flowConfig(t, url)
	cfg.RetryInterval = time.Millisecond
	cfg.Attempts = 5
	pub := testKey(t)
	var values map[string][]byte
	err := sidecar.Retry(context.Background(), cfg.Config, "secret", func(ctx context.Context) error {
		var err error
		values, err = fetchAllWith(ctx, cfg, http.DefaultClient, pub)
		return err
	})
	if err != nil {
		t.Fatalf("never released: %v", err)
	}
	if string(values["DB"]) != "released" {
		t.Fatalf("value = %q", values["DB"])
	}
	if cds.challenges < 3 {
		t.Fatalf("challenges = %d, want one per attempt", cds.challenges)
	}
}

// A bounded run that never gets released fails rather than idling in a Running
// pod with no secret.
func TestFetchWithRetryGivesUp(t *testing.T) {
	startInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/api/db": {{status: http.StatusForbidden}, {status: http.StatusForbidden}},
	})
	cfg := flowConfig(t, url)
	cfg.RetryInterval = time.Millisecond
	cfg.Attempts = 2
	pub := testKey(t)
	attempts := 0
	err := sidecar.Retry(context.Background(), cfg.Config, "secret", func(ctx context.Context) error {
		attempts++
		_, err := fetchAllWith(ctx, cfg, http.DefaultClient, pub)
		return err
	})
	if err == nil {
		t.Fatal("a permanently refused release reported success")
	}
	if attempts != cfg.Attempts {
		t.Fatalf("tried %d times, want %d", attempts, cfg.Attempts)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
