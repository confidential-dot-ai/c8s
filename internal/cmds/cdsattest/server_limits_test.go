package cdsattest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// countingEvidence reports how many attestation reports the endpoints minted.
type countingEvidence struct {
	inner FixtureEvidenceProvider
	calls atomic.Int64
}

func (c *countingEvidence) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	c.calls.Add(1)
	return c.inner.Evidence(ctx, reportData)
}

func testFixture() FixtureEvidenceProvider {
	return FixtureEvidenceProvider{
		Raw:        json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`),
		Platform:   "snp",
		Generation: "genoa",
	}
}

// newMeteredTestServer returns the sidecar, the httptest server in front of it
// and its evidence counter, so a test can inspect the state the endpoints fill.
// It runs the shipped limits.
func newMeteredTestServer(t *testing.T) (*Server, *httptest.Server, *countingEvidence) {
	t.Helper()
	return newBurstTestServer(t, 0)
}

// newBurstTestServer gives every limiter a refill too slow to matter, so a
// test asserts on the burst alone and never on wall-clock time. A burst of 0
// keeps the shipped limits.
func newBurstTestServer(t *testing.T, burst int) (*Server, *httptest.Server, *countingEvidence) {
	t.Helper()
	return newTestServerWith(t, func(srv *Server) {
		if burst > 0 {
			srv.establishLimiter = newLimiter(0.001, burst, clientBuckets)
			srv.sessionLimiter = newLimiter(0.001, burst, clientBuckets)
			srv.clientLimiter = newLimiter(0.001, burst, clientBuckets)
		}
	})
}

// newTestServerWith applies tune before the router is built, since the router
// binds the limiters it meters with.
func newTestServerWith(t *testing.T, tune func(*Server)) (*Server, *httptest.Server, *countingEvidence) {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	evidence := &countingEvidence{inner: testFixture()}
	srv := NewServer(Config{
		Evidence:             evidence,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	tune(srv)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, evidence
}

func testNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

// get issues a GET as the client X-Real-IP names and returns the status. An
// empty clientIP sends no header, as a caller that never passed the front door
// would.
func get(t *testing.T, url, clientIP string, headers ...string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if clientIP != "" {
		req.Header.Set("X-Real-IP", clientIP)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func getAttestPQ(t *testing.T, base, clientIP string, nonce []byte) int {
	t.Helper()
	return get(t, base+"/.well-known/c8s/attest-pq?nonce="+b64url(nonce), clientIP)
}

// TestAttestPQMetersEachClientSeparately spends one client's whole burst and
// checks every request past it is refused and that the count is exactly the
// burst, then that a second client still has its own.
func TestAttestPQMetersEachClientSeparately(t *testing.T) {
	const burst = 5
	_, ts, _ := newBurstTestServer(t, burst)

	var served, limited int
	for i := 0; i < 3*burst; i++ {
		switch code := getAttestPQ(t, ts.URL, "203.0.113.7", testNonce(t)); code {
		case http.StatusOK:
			served++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("attest-pq: unexpected status %d", code)
		}
	}
	if served != burst {
		t.Fatalf("one client was served %d attest-pq, want its burst of %d", served, burst)
	}
	if limited != 2*burst {
		t.Fatalf("%d requests were limited, want %d", limited, 2*burst)
	}
	if code := getAttestPQ(t, ts.URL, "198.51.100.9", testNonce(t)); code != http.StatusOK {
		t.Fatalf("attest-pq from a second client: got %d, want 200", code)
	}
}

// TestAttestLBAndHandshakeAreMetered pins the other two unauthenticated
// session-establishment routes onto the same budget.
func TestAttestLBAndHandshakeAreMetered(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             testFixture(),
		FrontDoorMode:        FrontDoorModeCDS,
		ServingCertFile:      identity.certFile,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	srv.establishLimiter = newLimiter(0.001, 1, clientBuckets)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if code := get(t, ts.URL+"/.well-known/c8s/attest-lb?nonce="+b64url(testNonce(t)), "203.0.113.7"); code != http.StatusOK {
		t.Fatalf("first attest-lb: got %d, want 200", code)
	}
	if code := get(t, ts.URL+"/.well-known/c8s/attest-lb?nonce="+b64url(testNonce(t)), "203.0.113.7"); code != http.StatusTooManyRequests {
		t.Fatalf("second attest-lb: got %d, want 429", code)
	}

	post := func(clientIP string) int {
		t.Helper()
		body, err := json.Marshal(types.HandshakeRequest{Nonce: b64url(testNonce(t))})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/handshake", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Real-IP", clientIP)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	// A second client's burst is untouched by the first's; its own second
	// handshake is refused.
	if code := post("198.51.100.9"); code == http.StatusTooManyRequests {
		t.Fatal("first handshake from a fresh client was rate limited")
	}
	if code := post("198.51.100.9"); code != http.StatusTooManyRequests {
		t.Fatalf("second handshake from the same client: got %d, want 429", code)
	}
}

// TestShippedBurstCoversASessionFleet drives whole sessions through the
// shipped constants. The load is stated here rather than derived from the
// constants, so tightening a limit past it fails this test: one client
// opening ten sessions back to back, which is a browser reloading a page.
func TestShippedBurstCoversASessionFleet(t *testing.T) {
	const legitimateSessions = 10

	_, ts, _ := newMeteredTestServer(t)

	// Each session costs one attest-pq and one handshake, and every request
	// here lands in the one bucket the client is charged.
	for i := 0; i < legitimateSessions; i++ {
		if _, id := establishSession(t, ts.URL, testNonce(t)); id == "" {
			t.Fatalf("session %d was not established", i)
		}
	}
}

// TestTunnelTrafficIsNotChargedToTheAttestationBudget runs an established
// session past the attestation burst: application traffic rides its own
// limiter, keyed on the session.
func TestTunnelTrafficIsNotChargedToTheAttestationBudget(t *testing.T) {
	_, ts, _ := newMeteredTestServer(t)

	const applicationRequests = 100

	nonce := testNonce(t)
	channel, sessionID := establishSession(t, ts.URL, nonce)
	for i := 0; i < applicationRequests; i++ {
		if code := tunnelStatus(t, ts.URL, sessionID, channel, i); code != http.StatusOK {
			t.Fatalf("tunnel request %d: got %d, want 200", i, code)
		}
	}
}

// TestSessionlessTunnelIsMetered pins the unauthenticated tunnel path, which
// costs a session lookup and nothing else, to the caller's own bucket.
func TestSessionlessTunnelIsMetered(t *testing.T) {
	_, ts, _ := newBurstTestServer(t, 2)

	post := func() int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader([]byte("junk")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Real-IP", "203.0.113.7")
		req.Header.Set(sessionHeader, "not-a-session-"+strconv.Itoa(int(time.Now().UnixNano())))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if code := post(); code != http.StatusUnauthorized {
		t.Fatalf("first sessionless tunnel: got %d, want 401", code)
	}
	if code := post(); code != http.StatusUnauthorized {
		t.Fatalf("second sessionless tunnel: got %d, want 401", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("third sessionless tunnel past the burst: got %d, want 429", code)
	}
}

// entitledClients is how many distinct clients a front door must be able to
// meter at once, stated here rather than read from the constant. A limiter
// refuses a client it has no bucket for, so this is an availability floor, and
// the ceiling below is a memory budget: three maps of this size at roughly a
// couple of hundred bytes a bucket.
const (
	entitledClients   = 50000
	affordableBuckets = 1 << 17
)

// TestLimiterMapsMeterAFleetOfClients pins the map size against that load
// rather than against itself.
func TestLimiterMapsMeterAFleetOfClients(t *testing.T) {
	if clientBuckets < entitledClients {
		t.Fatalf("a limiter meters %d clients at once, fewer than the %d a front door must serve", clientBuckets, entitledClients)
	}
	if clientBuckets > affordableBuckets {
		t.Fatalf("a limiter holds %d buckets, past the %d the sidecar budgets for", clientBuckets, affordableBuckets)
	}
}

// TestMaintenanceReclaimsQuietLimiterBuckets pins the loop that keeps the
// limiter maps off their ceiling. A map at capacity meters a smaller share of
// its traffic with every new client, since each one takes a bucket from the
// quietest, so the buckets of clients that have gone quiet have to come back.
func TestMaintenanceReclaimsQuietLimiterBuckets(t *testing.T) {
	const clients = 4
	srv, ts, _ := newTestServerWith(t, func(srv *Server) {
		srv.evictEvery = 5 * time.Millisecond
		srv.idleAfter = 20 * time.Millisecond
		srv.sweepEvery = time.Hour // not what this test is about
	})

	for i := 0; i < clients; i++ {
		if code := getAttestPQ(t, ts.URL, fmt.Sprintf("203.0.113.%d", i), testNonce(t)); code != http.StatusOK {
			t.Fatalf("client %d claiming a bucket: got %d, want 200", i, code)
		}
	}
	if got := srv.establishLimiter.Len(); got != clients {
		t.Fatalf("the limiter meters %d clients, want %d", got, clients)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.maintain(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for srv.establishLimiter.Len() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the limiter still meters %d clients that have gone quiet", srv.establishLimiter.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTimingsMeetTheirStatedRequirements pins the durations against what each
// one is for. Every bound here is a literal: a constant that only ever appears
// next to itself is not pinned by anything.
func TestTimingsMeetTheirStatedRequirements(t *testing.T) {
	for _, tc := range []struct {
		what     string
		got      time.Duration
		min, max time.Duration
		why      string
	}{
		{"nonce TTL", defaultNonceTTL, 10 * time.Second, time.Minute,
			"a client verifies a hardware report in between, on a phone; and a parked ML-KEM key is held for exactly this long"},
		{"sweep interval", sweepInterval, time.Second, 30 * time.Second,
			"expired entries hold their store's capacity until a sweep passes"},
		{"readiness cache", readyzCacheTTL, 200 * time.Millisecond, time.Second,
			"how stale an answer the kubelet may act on"},
		{"shutdown grace", shutdownGrace, time.Second, 30 * time.Second,
			"in-flight requests finish inside it, and a rollout waits on it"},
		{"limiter eviction interval", limiterEvictInterval, time.Second, 5 * time.Minute,
			"a client refused by a full map waits this long for a bucket"},
		{"limiter idle timeout", limiterIdleTimeout, time.Minute, 30 * time.Minute,
			"a bucket is held against a client that has gone quiet for this long"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			if tc.got < tc.min || tc.got > tc.max {
				t.Fatalf("%s is %v, want between %v and %v: %s", tc.what, tc.got, tc.min, tc.max, tc.why)
			}
		})
	}

	// A client opening sessions steadily, not in a burst, must still get
	// through: five a second is a browser reloading a page.
	const steadySessionsPerSecond = 5
	if establishRateLimit < 2*steadySessionsPerSecond {
		t.Fatalf("establishment is limited to %v/s, under the %d requests %d sessions a second cost",
			establishRateLimit, 2*steadySessionsPerSecond, steadySessionsPerSecond)
	}
}

// The memory each store may cost, stated as a budget rather than as the
// constants themselves. A ceiling exists to bound memory, so raising it is the
// dangerous direction and the one these bounds catch.
const (
	// A pending handshake holds an ML-KEM-768 decapsulation key and its public
	// key, about 4 KiB.
	pendingEntryBytes = 4 << 10
	pendingBudget     = 48 << 20
	// An established session holds a channel: two AEAD keys, a transcript and
	// a bounded replay set, about 1 KiB.
	sessionEntryBytes = 1 << 10
	sessionBudget     = 16 << 20
)

// TestStoresStayInsideTheirMemoryBudget pins the ceilings from above. A store
// bound is what stops an attacker turning traffic into memory, so it has to be
// small enough to matter, not only large enough to serve a fleet.
func TestStoresStayInsideTheirMemoryBudget(t *testing.T) {
	if cost := maxPendingSessions * pendingEntryBytes; cost > pendingBudget {
		t.Fatalf("the pending store may cost %d bytes, over its budget of %d", cost, pendingBudget)
	}
	if cost := maxSessions * sessionEntryBytes; cost > sessionBudget {
		t.Fatalf("the session pool may cost %d bytes, over its budget of %d", cost, sessionBudget)
	}
	// And no single client may hold more than an eighth of either store,
	// however generous the per-client tier is to a crowd behind one address.
	if maxSessionsPerClient > maxSessions/8 {
		t.Fatalf("one client may hold %d of %d sessions, more than an eighth of the pool", maxSessionsPerClient, maxSessions)
	}
	if maxPendingPerClient > maxPendingSessions/8 {
		t.Fatalf("one client may hold %d of %d handshakes, more than an eighth of the store", maxPendingPerClient, maxPendingSessions)
	}
}

// TestLimiterMapsHoldTheirWholeKeySpace pins the relationship between the
// stores and the maps that meter them. A limiter refuses a key it has no
// bucket for, and the session limiter is keyed by session as well as by
// client, so a map smaller than the session store turns a full store into a
// denial on live sessions.
func TestLimiterMapsHoldTheirWholeKeySpace(t *testing.T) {
	if sessionBuckets <= maxSessions {
		t.Fatalf("the session limiter holds %d buckets for a store of %d sessions", sessionBuckets, maxSessions)
	}
	if sessionBuckets < maxSessions+clientBuckets {
		t.Fatalf("the session limiter holds %d buckets, want room for %d sessions and %d clients", sessionBuckets, maxSessions, clientBuckets)
	}
	if clientBuckets <= maxSessions/maxSessionsPerClient {
		t.Fatalf("the client limiter holds %d buckets, fewer than the %d clients that can fill the session store", clientBuckets, maxSessions/maxSessionsPerClient)
	}
}

// TestSessionlessFloodCannotDenyALiveSession is that relationship from the
// outside: sessionless tunnel posts from many distinct prefixes each claim a
// bucket in the same limiter the live sessions are keyed in, and a client
// holding a live session must keep being served through it.
func TestSessionlessFloodCannotDenyALiveSession(t *testing.T) {
	// Enough churn to move buckets around the map the live session is keyed
	// in. What pins the map's size is TestLimiterMapsHoldTheirWholeKeySpace;
	// this pins the symptom that sizing was wrong for — a live session
	// refused — which no amount of churn may cause.
	const floodPrefixes = 2000

	_, ts, _ := newMeteredTestServer(t)
	channel, sessionID := establishSession(t, ts.URL, testNonce(t))

	client := &http.Client{}
	for i := 0; i < floodPrefixes; i++ {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader([]byte("junk")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Real-IP", fmt.Sprintf("2001:db8:%x:%x::1", i/65536, i%65536))
		req.Header.Set(sessionHeader, fmt.Sprintf("no-such-session-%d", i))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if code := tunnelStatus(t, ts.URL, sessionID, channel, 0); code != http.StatusOK {
		t.Fatalf("a live session got %d after %d sessionless prefixes flooded the tunnel, want 200", code, floodPrefixes)
	}
}

// TestTunnelKeyChargesOnlyLiveSessions pins that an invented session id cannot
// name a bucket of its own.
func TestTunnelKeyChargesOnlyLiveSessions(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	srv.sessions["live"] = establishedSession{lastUsed: time.Now()}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Real-IP", "203.0.113.7")

	req.Header.Set(sessionHeader, "live")
	if got := srv.tunnelKey(req); got != "session:live" {
		t.Fatalf("tunnelKey for a live session = %q", got)
	}
	req.Header.Set(sessionHeader, "invented")
	if got := srv.tunnelKey(req); got != "client:203.0.113.7" {
		t.Fatalf("tunnelKey for an invented session = %q, want the client bucket", got)
	}
	req.Header.Del(sessionHeader)
	if got := srv.tunnelKey(req); got != "client:203.0.113.7" {
		t.Fatalf("tunnelKey without a session = %q, want the client bucket", got)
	}
}

// TestClientKeyOnlyTrustsTheFrontDoor pins where the bucket comes from: nginx
// sets X-Real-IP on the loopback hop, nothing else is consulted, and an IPv6
// client is charged to the /64 its provider assigned it rather than to an
// address it can pick 2^64 of.
func TestClientKeyOnlyTrustsTheFrontDoor(t *testing.T) {
	cases := []struct {
		name, remoteAddr, want string
		headers                []string
	}{
		{name: "front door names the client", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Real-IP", "203.0.113.7"}, want: "client:203.0.113.7"},
		{name: "IPv6 loopback front door", remoteAddr: "[::1]:5555", headers: []string{"X-Real-IP", "203.0.113.7"}, want: "client:203.0.113.7"},
		{name: "IPv6 client is charged to its /64", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Real-IP", "2001:db8:1:2::1"}, want: "client:2001:db8:1:2::/64"},
		{name: "another address in that /64 is the same bucket", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Real-IP", "2001:db8:1:2:ffff:ffff:ffff:ffff"}, want: "client:2001:db8:1:2::/64"},
		{name: "the neighbouring /64 is a different bucket", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Real-IP", "2001:db8:1:3::1"}, want: "client:2001:db8:1:3::/64"},
		{name: "direct caller cannot name a bucket", remoteAddr: "203.0.113.7:5555", headers: []string{"X-Real-IP", "198.51.100.9"}, want: ""},
		{name: "direct caller cannot name a bucket with X-Forwarded-For", remoteAddr: "203.0.113.7:5555", headers: []string{"X-Forwarded-For", "198.51.100.9"}, want: ""},
		{name: "direct caller cannot name a bucket with either header", remoteAddr: "203.0.113.7:5555", headers: []string{"X-Real-IP", "198.51.100.9", "X-Forwarded-For", "192.0.2.1"}, want: ""},
		{name: "front door without the header", remoteAddr: "127.0.0.1:5555", want: ""},
		{name: "unparseable header", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Real-IP", "not-an-ip"}, want: ""},
		{name: "X-Forwarded-For is never consulted", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Forwarded-For", "198.51.100.9"}, want: ""},
		{name: "X-Forwarded-For does not override X-Real-IP", remoteAddr: "127.0.0.1:5555", headers: []string{"X-Real-IP", "203.0.113.7", "X-Forwarded-For", "198.51.100.9"}, want: "client:203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			for i := 0; i+1 < len(tc.headers); i += 2 {
				r.Header.Set(tc.headers[i], tc.headers[i+1])
			}
			if got := clientKey(r); got != tc.want {
				t.Fatalf("clientKey = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIPv6ClientsShareTheirPrefixBucket asserts on the bucket the limiter
// actually charged: one /64 is one budget, and the next /64 is its own.
func TestIPv6ClientsShareTheirPrefixBucket(t *testing.T) {
	_, ts, _ := newBurstTestServer(t, 1)

	first := ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(testNonce(t))
	if code := get(t, first, "2001:db8:1:2::1"); code != http.StatusOK {
		t.Fatalf("first request from the /64: got %d, want 200", code)
	}
	second := ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(testNonce(t))
	if code := get(t, second, "2001:db8:1:2:aaaa::9"); code != http.StatusTooManyRequests {
		t.Fatalf("second address in the same /64: got %d, want 429", code)
	}
	third := ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(testNonce(t))
	if code := get(t, third, "2001:db8:1:3::1"); code != http.StatusOK {
		t.Fatalf("first request from a neighbouring /64: got %d, want 200", code)
	}
}

// TestForwardedForCannotSplitTheBucket spends a burst under one X-Real-IP
// while varying X-Forwarded-For, so the assertion is on the bucket the
// limiter actually charged rather than on a key function's return value.
func TestForwardedForCannotSplitTheBucket(t *testing.T) {
	_, ts, _ := newBurstTestServer(t, 1)

	url := ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(testNonce(t))
	if code := get(t, url, "203.0.113.7", "X-Forwarded-For", "10.0.0.1"); code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", code)
	}
	url = ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(testNonce(t))
	if code := get(t, url, "203.0.113.7", "X-Forwarded-For", "10.0.0.2"); code != http.StatusTooManyRequests {
		t.Fatalf("second request behind a different X-Forwarded-For: got %d, want 429", code)
	}
}

// TestPendingEvictsTheClientsOwnOldest pins what a client past its bound
// loses: its own oldest handshake, not the request it just made and not
// another client's entry.
func TestPendingEvictsTheClientsOwnOldest(t *testing.T) {
	// The per-client bound, not the rate, is what this test drives.
	srv, ts, _ := newBurstTestServer(t, 4*maxPendingPerClient)

	firstNonce := testNonce(t)
	if code := getAttestPQ(t, ts.URL, "203.0.113.7", firstNonce); code != http.StatusOK {
		t.Fatalf("first attest-pq: got %d, want 200", code)
	}
	// The rest of the client's bound is filled directly: the requests this
	// test is about are the first, which must survive, and the two at the
	// boundary. Minting five hundred ML-KEM keys over HTTP adds nothing.
	for i := 1; i < maxPendingPerClient-1; i++ {
		if err := srv.addPending("client:203.0.113.7", fmt.Sprintf("filler-%d", i), pendingSession{createdAt: time.Now()}); err != nil {
			t.Fatalf("filling to one under the bound: %v", err)
		}
	}
	if code := getAttestPQ(t, ts.URL, "203.0.113.7", testNonce(t)); code != http.StatusOK {
		t.Fatalf("attest-pq at the bound: got %d, want 200", code)
	}
	// A neighbour's entry, parked before the bound is crossed.
	neighbourNonce := testNonce(t)
	if code := getAttestPQ(t, ts.URL, "198.51.100.9", neighbourNonce); code != http.StatusOK {
		t.Fatalf("attest-pq from a second client: got %d, want 200", code)
	}

	if code := getAttestPQ(t, ts.URL, "203.0.113.7", testNonce(t)); code != http.StatusOK {
		t.Fatalf("attest-pq past the bound: got %d, want 200", code)
	}

	srv.mu.Lock()
	held := srv.pendingBy.count("client:203.0.113.7")
	_, firstKept := srv.pending[b64url(firstNonce)]
	_, neighbourKept := srv.pending[b64url(neighbourNonce)]
	srv.mu.Unlock()
	if held != maxPendingPerClient {
		t.Fatalf("client holds %d pending handshakes, want %d", held, maxPendingPerClient)
	}
	if firstKept {
		t.Fatal("the client's oldest handshake survived its own overflow")
	}
	if !neighbourKept {
		t.Fatal("a second client's handshake was evicted by the first's overflow")
	}
}

// TestRefusedAttestPQMintsNoEvidence pins that the one attest-pq refusal — a
// nonce already pending — is decided before the hardware report is pulled.
func TestRefusedAttestPQMintsNoEvidence(t *testing.T) {
	_, ts, evidence := newMeteredTestServer(t)

	nonce := testNonce(t)
	if code := getAttestPQ(t, ts.URL, "203.0.113.7", nonce); code != http.StatusOK {
		t.Fatalf("first attest-pq: got %d, want 200", code)
	}
	minted := evidence.calls.Load()

	for i := 0; i < 5; i++ {
		if code := getAttestPQ(t, ts.URL, "198.51.100.9", nonce); code != http.StatusConflict {
			t.Fatalf("attest-pq reusing a pending nonce: got %d, want 409", code)
		}
	}
	if got := evidence.calls.Load(); got != minted {
		t.Fatalf("refused requests minted %d reports, want 0", got-minted)
	}
}

// TestAddPendingRefusesADuplicateNonce asserts the collision check where it
// has to live — inside the insert — rather than through the endpoint, whose
// earlier check would answer for it.
func TestAddPendingRefusesADuplicateNonce(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	first := pendingSession{createdAt: time.Now()}
	if err := srv.addPending("client:first", "shared-nonce", first); err != nil {
		t.Fatal(err)
	}
	if err := srv.addPending("client:second", "shared-nonce", pendingSession{createdAt: time.Now()}); err == nil {
		t.Fatal("a second client parked a handshake under a nonce already pending")
	}

	srv.mu.Lock()
	held := len(srv.pending)
	kept := srv.pending["shared-nonce"]
	second := srv.pendingBy.count("client:second")
	srv.mu.Unlock()
	if held != 1 {
		t.Fatalf("store holds %d entries, want 1", held)
	}
	if kept.client != "client:first" {
		t.Fatalf("the entry is charged to %q, want the client that took the nonce", kept.client)
	}
	if second != 0 {
		t.Fatalf("the refused client is charged %d entries, want 0", second)
	}
}

// TestPendingNonceIsNeverOverwritten pins that a second attest-pq under a
// nonce already pending cannot replace the first client's handshake key.
func TestPendingNonceIsNeverOverwritten(t *testing.T) {
	srv, ts, _ := newMeteredTestServer(t)

	nonce := testNonce(t)
	if code := getAttestPQ(t, ts.URL, "203.0.113.7", nonce); code != http.StatusOK {
		t.Fatalf("first attest-pq: got %d, want 200", code)
	}
	srv.mu.Lock()
	first := srv.pending[b64url(nonce)].key
	srv.mu.Unlock()

	if code := getAttestPQ(t, ts.URL, "198.51.100.9", nonce); code != http.StatusConflict {
		t.Fatalf("attest-pq reusing a pending nonce: got %d, want 409", code)
	}
	srv.mu.Lock()
	after := srv.pending[b64url(nonce)].key
	held := srv.pendingBy.count("client:198.51.100.9")
	srv.mu.Unlock()
	if after != first {
		t.Fatal("a second client's attest-pq replaced the pending handshake key")
	}
	if held != 0 {
		t.Fatalf("the refused client is accounted %d pending handshakes, want 0", held)
	}
}

// raceRounds: two goroutines can only be inside a check-then-act window at
// once when they truly run at once, so these rounds buy little on a runner
// with few processors. The invariants they cover are also asserted directly,
// without a race, by TestAddPendingRefusesADuplicateNonce and
// TestPendingEvictsTheClientsOwnOldest.
// noteRaceCoverage says out loud when a barrier test cannot do its job: with
// one processor two goroutines never sit inside the window it guards, so it
// passes without covering anything.
func noteRaceCoverage(t *testing.T) {
	t.Helper()
	if runtime.GOMAXPROCS(0) == 1 {
		t.Log("GOMAXPROCS=1: this test cannot interleave two goroutines, so it covers nothing here")
	}
}

func raceRounds() int {
	if runtime.GOMAXPROCS(0) >= 8 {
		return 200
	}
	return 500
}

// TestPendingHoldsTheBoundUnderConcurrency releases a crowd of inserts at a
// client already at its bound, round after round: the bound check, the
// eviction and the insert must be one critical section, or a round leaves the
// client holding more than its bound. Every insert past the bound costs the
// client one of its own, so the store stays at the bound across rounds.
func TestPendingHoldsTheBoundUnderConcurrency(t *testing.T) {
	const (
		client = "client:203.0.113.7"
		racers = 64
	)
	noteRaceCoverage(t)
	srv, _, _ := newMeteredTestServer(t)

	for i := 0; i < maxPendingPerClient; i++ {
		if err := srv.addPending(client, fmt.Sprintf("held-%d", i), pendingSession{createdAt: time.Now()}); err != nil {
			t.Fatalf("filling to the bound: %v", err)
		}
	}

	for round := 0; round < raceRounds(); round++ {
		// One under the bound, so the racers contend for the last free slot
		// rather than all reading a full store.
		srv.mu.Lock()
		for _, nonce := range sortedKeys(srv.pendingBy.keys(client))[:1] {
			srv.dropPending(nonce)
		}
		srv.mu.Unlock()

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_ = srv.addPending(client, fmt.Sprintf("racer-%d-%d", round, i), pendingSession{createdAt: time.Now()})
			}(i)
		}
		close(start)
		wg.Wait()

		srv.mu.Lock()
		held, counted := len(srv.pending), srv.pendingBy.count(client)
		srv.mu.Unlock()
		if held != maxPendingPerClient || counted != maxPendingPerClient {
			t.Fatalf("round %d: store holds %d entries and counts %d, want %d of each", round, held, counted, maxPendingPerClient)
		}
	}
}

// sortedKeys is a deterministic order over a holder's keys.
func sortedKeys(held map[string]struct{}) []string {
	keys := make([]string, 0, len(held))
	for key := range held {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// TestSessionBoundHoldsUnderConcurrency races inserts at a client one under
// its session bound. Refusing there is a plain count-then-insert, so the two
// have to be one critical section or a client ends up holding more sessions
// than its bound allows.
func TestSessionBoundHoldsUnderConcurrency(t *testing.T) {
	const (
		client = "client:203.0.113.7"
		racers = 256
	)
	noteRaceCoverage(t)
	srv, _, _ := newMeteredTestServer(t)

	for i := 0; i < maxSessionsPerClient-1; i++ {
		if err := srv.addSession(client, fmt.Sprintf("held-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("filling to one under the bound: %v", err)
		}
	}

	for round := 0; round < raceRounds(); round++ {
		var wg sync.WaitGroup
		var accepted atomic.Int64
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if err := srv.addSession(client, fmt.Sprintf("racer-%d-%d", round, i), establishedSession{lastUsed: time.Now()}); err == nil {
					accepted.Add(1)
				}
			}(i)
		}
		close(start)
		wg.Wait()

		srv.mu.Lock()
		held := srv.sessionsBy.count(client)
		srv.mu.Unlock()
		if got := accepted.Load(); got != 1 {
			t.Fatalf("round %d: %d racing inserts took the one free slot, want 1", round, got)
		}
		if held != maxSessionsPerClient {
			t.Fatalf("round %d: client holds %d sessions, want %d", round, held, maxSessionsPerClient)
		}
		// Back to one under the bound for the next round.
		srv.mu.Lock()
		srv.dropSession(sortedKeys(srv.sessionsBy.keys(client))[0])
		srv.mu.Unlock()
	}
}

// TestPendingNonceCollidesUnderConcurrency races two clients onto one nonce:
// the collision check must sit inside the lock that inserts, or both are
// charged for an entry only one of them holds.
func TestPendingNonceCollidesUnderConcurrency(t *testing.T) {
	const racers = 256
	srv, _, _ := newMeteredTestServer(t)

	for round := 0; round < raceRounds(); round++ {
		srv.mu.Lock()
		srv.pending = make(map[string]pendingSession)
		srv.pendingBy = newHolders()
		srv.mu.Unlock()

		nonce := fmt.Sprintf("contested-%d", round)
		var wg sync.WaitGroup
		var accepted atomic.Int64
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if err := srv.addPending(fmt.Sprintf("client:%d", i), nonce, pendingSession{createdAt: time.Now()}); err == nil {
					accepted.Add(1)
				}
			}(i)
		}
		close(start)
		wg.Wait()

		srv.mu.Lock()
		held, clients := len(srv.pending), srv.pendingBy.clients()
		srv.mu.Unlock()
		if got := accepted.Load(); got != 1 {
			t.Fatalf("round %d: %d clients were accepted onto one nonce, want 1", round, got)
		}
		if held != 1 || clients != 1 {
			t.Fatalf("round %d: store holds %d entries charged to %d clients, want 1 and 1", round, held, clients)
		}
	}
}

// TestPendingGlobalBoundDropsFromTheLargestHolder pins the memory ceiling on
// pending handshakes: past it the entry dropped belongs to whoever holds the
// most, so a client holding one keeps it.
func TestPendingGlobalBoundDropsFromTheLargestHolder(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	// A victim that arrived first and holds a single, therefore oldest, entry.
	if err := srv.addPending("client:victim", "victim-nonce", pendingSession{createdAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Second)
	for i := 1; i < maxPendingSessions; i++ {
		client := fmt.Sprintf("client:flooder-%d", i/maxPendingPerClient)
		if err := srv.addPending(client, fmt.Sprintf("nonce-%d", i), pendingSession{createdAt: now.Add(time.Duration(i) * time.Millisecond)}); err != nil {
			t.Fatalf("filling the store at %d: %v", i, err)
		}
	}

	if err := srv.addPending("client:newcomer", "newcomer", pendingSession{createdAt: time.Now()}); err != nil {
		t.Fatalf("insert into a full store: %v", err)
	}

	srv.mu.Lock()
	held := len(srv.pending)
	_, victimKept := srv.pending["victim-nonce"]
	_, newcomerKept := srv.pending["newcomer"]
	flooders := 0
	for client := range srv.pendingBy.byClient {
		if strings.HasPrefix(client, "client:flooder-") {
			flooders += srv.pendingBy.count(client)
		}
	}
	srv.mu.Unlock()

	if held != maxPendingSessions {
		t.Fatalf("store holds %d entries, want %d", held, maxPendingSessions)
	}
	if !victimKept {
		t.Fatal("the oldest entry was dropped although its client held only one")
	}
	if !newcomerKept {
		t.Fatal("the new pending handshake was not stored")
	}
	// The victim and the newcomer hold one each; every other entry, and the
	// one dropped to make room, belongs to a flooder.
	if want := maxPendingSessions - 2; flooders != want {
		t.Fatalf("the flooders hold %d entries, want %d", flooders, want)
	}
}

// TestPendingFullStoreAdmitsAClientHoldingNothing mirrors the session rule on
// the handshake store.
func TestPendingFullStoreAdmitsAClientHoldingNothing(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	for i := 0; i < maxPendingSessions; i++ {
		client := fmt.Sprintf("client:holder-%d", i/maxPendingPerClient)
		if err := srv.addPending(client, fmt.Sprintf("nonce-%d", i), pendingSession{createdAt: time.Now()}); err != nil {
			t.Fatalf("filling the store at %d: %v", i, err)
		}
	}
	if err := srv.addPending("client:newcomer", "newcomer", pendingSession{createdAt: time.Now()}); err != nil {
		t.Fatalf("a client holding nothing was refused by a full store: %v", err)
	}
}

// TestPendingRefusesOnceEveryHolderIsAtTheFloor pins the endpoint's answer
// when the store has nothing to give up: a 503 the client can retry, and no
// attestation minted for it.
func TestPendingRefusesOnceEveryHolderIsAtTheFloor(t *testing.T) {
	srv, ts, evidence := newMeteredTestServer(t)

	for i := 0; i < maxPendingSessions; i++ {
		client := fmt.Sprintf("client:holder-%d", i/minShare)
		if err := srv.addPending(client, fmt.Sprintf("nonce-%d", i), pendingSession{createdAt: time.Now()}); err != nil {
			t.Fatalf("filling the store at %d: %v", i, err)
		}
	}
	if err := srv.addPending("client:newcomer", "newcomer", pendingSession{createdAt: time.Now()}); !errors.Is(err, errStoreFull) {
		t.Fatalf("insert into a store level at the floor: %v, want it refused", err)
	}

	minted := evidence.calls.Load()
	for i := 0; i < 5; i++ {
		if code := getAttestPQ(t, ts.URL, "203.0.113.7", testNonce(t)); code != http.StatusServiceUnavailable {
			t.Fatalf("attest-pq against a store with nothing to give up: got %d, want 503", code)
		}
	}
	if got := evidence.calls.Load(); got != minted {
		t.Fatalf("refused attest-pq minted %d reports, want 0", got-minted)
	}

	srv.mu.Lock()
	held := len(srv.pending)
	srv.mu.Unlock()
	if held != maxPendingSessions {
		t.Fatalf("store holds %d entries, want %d", held, maxPendingSessions)
	}
}

// TestRefuseSessionSeparatesACollisionFromALimit pins that a 128-bit id
// collision is reported as this server's fault, not as the caller's rate.
func TestRefuseSessionSeparatesACollisionFromALimit(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"id collision", errSessionInUse, http.StatusInternalServerError},
		{"store full", errStoreFull, http.StatusServiceUnavailable},
		{"client at its bound", errSessionsFull, http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			srv.refuseSession(w, tc.err)
			if w.Code != tc.want {
				t.Fatalf("refuseSession(%v) = %d, want %d", tc.err, w.Code, tc.want)
			}
		})
	}
}

// TestSessionsAreBoundedPerClient pins that established sessions are counted
// per client too: pending is a flow, and only this bounds the stock.
func TestSessionsAreBoundedPerClient(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	const client = "client:203.0.113.7"

	for i := 0; i < maxSessionsPerClient; i++ {
		if err := srv.addSession(client, "session-"+strconv.Itoa(i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("session %d under the bound: %v", i, err)
		}
	}
	if err := srv.addSession(client, "one-too-many", establishedSession{lastUsed: time.Now()}); err == nil {
		t.Fatal("a client opened more sessions than its bound")
	}
	if err := srv.addSession("client:198.51.100.9", "other-client", establishedSession{lastUsed: time.Now()}); err != nil {
		t.Fatalf("session for a client holding none: %v", err)
	}
}

// The concurrency one address is entitled to, stated here rather than derived
// from the bounds, so shrinking a bound fails this test. One public address
// fronts a CGNAT or a corporate egress, so it stands for a crowd: 500
// simultaneous sessions and 500 handshakes in flight behind one address.
const (
	entitledSessions = 500
	entitledPending  = 500
	// And the store as a whole holds a fleet of those crowds.
	entitledStore = 8000
)

// TestOneAddressMayHoldACrowdsWorthOfSessions pins the per-client session
// bound against a number a NAT actually reaches.
func TestOneAddressMayHoldACrowdsWorthOfSessions(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	for i := 0; i < entitledSessions; i++ {
		if err := srv.addSession("client:203.0.113.7", fmt.Sprintf("session-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("session %d of one address: %v", i, err)
		}
	}
}

// TestOneAddressMayHoldACrowdsWorthOfHandshakes pins the same for handshakes
// in flight: past the bound the oldest is dropped, so the assertion is that
// the crowd's own entries are all still there.
func TestOneAddressMayHoldACrowdsWorthOfHandshakes(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	for i := 0; i < entitledPending; i++ {
		if err := srv.addPending("client:203.0.113.7", fmt.Sprintf("nonce-%d", i), pendingSession{createdAt: time.Now()}); err != nil {
			t.Fatalf("handshake %d of one address: %v", i, err)
		}
	}
	srv.mu.Lock()
	held := srv.pendingBy.count("client:203.0.113.7")
	srv.mu.Unlock()
	if held != entitledPending {
		t.Fatalf("one address holds %d handshakes of %d it started, want all of them", held, entitledPending)
	}
}

// TestTheStoresHoldAFleet pins the global bounds against a number of clients
// rather than against themselves.
func TestTheStoresHoldAFleet(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	for i := 0; i < entitledStore; i++ {
		client := fmt.Sprintf("client:%d", i%64)
		if err := srv.addSession(client, fmt.Sprintf("session-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("session %d of a fleet: %v", i, err)
		}
		if err := srv.addPending(client, fmt.Sprintf("nonce-%d", i), pendingSession{createdAt: time.Now()}); err != nil {
			t.Fatalf("handshake %d of a fleet: %v", i, err)
		}
	}
	srv.mu.Lock()
	sessions, pending := len(srv.sessions), len(srv.pending)
	srv.mu.Unlock()
	if sessions != entitledStore || pending != entitledStore {
		t.Fatalf("the stores hold %d sessions and %d handshakes, want %d of each", sessions, pending, entitledStore)
	}
}

// TestEvictionPicksTheIdlestWithinAHolder pins the choice inside the client a
// full store takes from: the entry closest to being given up anyway, not the
// one in use.
func TestEvictionPicksTheIdlestWithinAHolder(t *testing.T) {
	now := time.Now()
	sessions := map[string]establishedSession{
		"busy":   {lastUsed: now},
		"idle":   {lastUsed: now.Add(-time.Hour)},
		"middle": {lastUsed: now.Add(-time.Minute)},
	}
	held := map[string]struct{}{"busy": {}, "idle": {}, "middle": {}}
	if got := idlestSessionOf(sessions, held); got != "idle" {
		t.Fatalf("idlestSessionOf = %q, want idle", got)
	}

	pending := map[string]pendingSession{
		"new":    {createdAt: now},
		"oldest": {createdAt: now.Add(-time.Hour)},
		"middle": {createdAt: now.Add(-time.Minute)},
	}
	heldNonces := map[string]struct{}{"new": {}, "oldest": {}, "middle": {}}
	if got := oldestPendingOf(pending, heldNonces); got != "oldest" {
		t.Fatalf("oldestPendingOf = %q, want oldest", got)
	}
}

// TestFloodCannotEvictAnHonestSession is the guarantee the global session
// bound has to make: an attacker saturating the pool from many addresses, and
// keeping what it holds warm, still cannot take a session away from a client
// holding one. Eviction by idleness would hand it over — a client waiting on a
// long completion is the idlest thing in the pool.
func TestFloodCannotEvictAnHonestSession(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	honest := establishedSession{lastUsed: time.Now()}
	if err := srv.addSession("client:honest", "honest-session", honest); err != nil {
		t.Fatal(err)
	}

	// The attacker fills the pool: every address at its per-client bound.
	warm := time.Now().Add(time.Minute)
	for i := 1; i < maxSessions; i++ {
		client := fmt.Sprintf("client:flooder-%d", i/maxSessionsPerClient)
		if err := srv.addSession(client, fmt.Sprintf("session-%d", i), establishedSession{lastUsed: warm}); err != nil {
			t.Fatalf("filling the pool at %d: %v", i, err)
		}
	}

	// It then keeps churning: every insert past the bound must cost it one of
	// its own, however idle the honest session looks next to its warm ones.
	for i := 0; i < 4*maxSessionsPerClient; i++ {
		client := fmt.Sprintf("client:churn-%d", i/maxSessionsPerClient)
		if err := srv.addSession(client, fmt.Sprintf("churn-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("attacker insert %d into a full pool: %v", i, err)
		}
		srv.mu.Lock()
		_, kept := srv.sessions["honest-session"]
		srv.mu.Unlock()
		if !kept {
			t.Fatalf("the honest session was evicted after %d attacker inserts", i+1)
		}
	}

	srv.mu.Lock()
	held := len(srv.sessions)
	honestHeld := srv.sessionsBy.count("client:honest")
	srv.mu.Unlock()
	if held != maxSessions {
		t.Fatalf("pool holds %d sessions, want %d", held, maxSessions)
	}
	if honestHeld != 1 {
		t.Fatalf("the honest client is accounted %d sessions, want 1", honestHeld)
	}
}

// fillSessions puts one session under each of clients[i], cycling, until the
// pool holds want entries.
func fillSessions(t *testing.T, srv *Server, want int, clients func(i int) string) {
	t.Helper()
	for i := 0; srv.sessionCount() < want; i++ {
		if err := srv.addSession(clients(i), fmt.Sprintf("session-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("filling the pool at %d: %v", i, err)
		}
	}
}

func (s *Server) sessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// TestFullStoreAdmitsAClientHoldingNothing pins the admission rule from the
// side that matters to a first-time caller: a pool held entirely by clients at
// the per-client bound still has room for one holding nothing, because the
// share is divided between the holders and the caller.
func TestFullStoreAdmitsAClientHoldingNothing(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	fillSessions(t, srv, maxSessions, func(i int) string {
		return fmt.Sprintf("client:holder-%d", i/maxSessionsPerClient)
	})

	if err := srv.addSession("client:newcomer", "newcomer", establishedSession{lastUsed: time.Now()}); err != nil {
		t.Fatalf("a client holding nothing was refused by a full pool: %v", err)
	}

	srv.mu.Lock()
	held := len(srv.sessions)
	_, kept := srv.sessions["newcomer"]
	newcomer := srv.sessionsBy.count("client:newcomer")
	srv.mu.Unlock()
	if held != maxSessions {
		t.Fatalf("pool holds %d sessions, want %d", held, maxSessions)
	}
	if !kept || newcomer != 1 {
		t.Fatalf("the newcomer holds %d sessions and is stored: %v", newcomer, kept)
	}
}

// TestFullStoreRefusesOnceEveryHolderIsAtTheFloor pins where admission stops.
// The floor is a constant, so the number of clients it takes to reach this is
// ours to set — capacity/minShare — not something an attacker can lower.
func TestFullStoreRefusesOnceEveryHolderIsAtTheFloor(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	fillSessions(t, srv, maxSessions, func(i int) string {
		return fmt.Sprintf("client:holder-%d", i/minShare)
	})

	srv.mu.Lock()
	holders := srv.sessionsBy.clients()
	srv.mu.Unlock()
	if holders != maxSessions/minShare {
		t.Fatalf("pool is held by %d clients, want %d", holders, maxSessions/minShare)
	}

	if err := srv.addSession("client:newcomer", "newcomer", establishedSession{lastUsed: time.Now()}); !errors.Is(err, errStoreFull) {
		t.Fatalf("insert into a pool level at the floor: %v, want it refused", err)
	}

	srv.mu.Lock()
	held := len(srv.sessions)
	first := srv.sessionsBy.count("client:holder-0")
	srv.mu.Unlock()
	if held != maxSessions {
		t.Fatalf("pool holds %d sessions, want %d", held, maxSessions)
	}
	if first != minShare {
		t.Fatalf("a holder at the floor holds %d sessions, want %d", first, minShare)
	}
}

// TestFullStoreGivesUpAnEntryOnlyFromAClientOverItsShare pins the other half:
// a client above the share is what a full pool takes from, and its accounting
// is released with the entry.
func TestFullStoreGivesUpAnEntryOnlyFromAClientOverItsShare(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	// One client at its bound alongside many holding a single session: the
	// share is small, so the big holder is well above it.
	const hogs = 4
	fillSessions(t, srv, maxSessions, func(i int) string {
		if i < hogs*maxSessionsPerClient {
			return fmt.Sprintf("client:hog-%d", i/maxSessionsPerClient)
		}
		return fmt.Sprintf("client:small-%d", i)
	})

	before := srv.sessionsBy.count("client:hog-0") + srv.sessionsBy.count("client:hog-1") +
		srv.sessionsBy.count("client:hog-2") + srv.sessionsBy.count("client:hog-3")
	if err := srv.addSession("client:newcomer", "newcomer", establishedSession{lastUsed: time.Now()}); err != nil {
		t.Fatalf("insert into a pool with a client over its share: %v", err)
	}

	srv.mu.Lock()
	held := len(srv.sessions)
	after := srv.sessionsBy.count("client:hog-0") + srv.sessionsBy.count("client:hog-1") +
		srv.sessionsBy.count("client:hog-2") + srv.sessionsBy.count("client:hog-3")
	_, newcomerKept := srv.sessions["newcomer"]
	counted := 0
	for client := range srv.sessionsBy.byClient {
		counted += srv.sessionsBy.count(client)
	}
	srv.mu.Unlock()

	if held != maxSessions {
		t.Fatalf("pool holds %d sessions, want %d", held, maxSessions)
	}
	if !newcomerKept {
		t.Fatal("the newcomer was not stored")
	}
	if after != before-1 {
		t.Fatalf("the clients over their share hold %d sessions, want %d", after, before-1)
	}
	if counted != held {
		t.Fatalf("clients are charged for %d sessions but the pool holds %d", counted, held)
	}
}

// entitledFloor is what a client keeps whatever an attacker spends on
// addresses, stated here rather than read from minShare so that lowering the
// floor fails this test. Eight concurrent sessions is a browser with a handful
// of tabs open.
const entitledFloor = 8

// TestDrainStopsAtTheFloor is the property that ends the drain: an attacker
// adding addresses divides the share further, so it decides how much a victim
// gives up — but not past a floor this code sets, and never below what a
// client is entitled to keep.
func TestDrainStopsAtTheFloor(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	const victim = "client:victim"
	for i := 0; i < maxSessionsPerClient; i++ {
		if err := srv.addSession(victim, fmt.Sprintf("victim-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("victim session %d: %v", i, err)
		}
	}
	fillSessions(t, srv, maxSessions, func(i int) string { return fmt.Sprintf("client:flooder-%d", i/maxSessionsPerClient) })

	// Every address the attacker adds divides the share further; none of them
	// may push the victim below the floor. The store settles well inside this,
	// and every insert past that is a refusal re-asserting the same state.
	for i := 0; i < 2*maxSessions; i++ {
		_ = srv.addSession(fmt.Sprintf("client:churn-%d", i), fmt.Sprintf("churn-%d", i), establishedSession{lastUsed: time.Now()})

		srv.mu.Lock()
		held := srv.sessionsBy.count(victim)
		srv.mu.Unlock()
		if held < entitledFloor {
			t.Fatalf("insert %d drained the victim to %d sessions, below the %d it is entitled to keep", i, held, entitledFloor)
		}
	}

	srv.mu.Lock()
	held, holders := srv.sessionsBy.count(victim), srv.sessionsBy.clients()
	srv.mu.Unlock()
	// Equality, not a lower bound: a store that evicts nothing at all would
	// leave the victim untouched at its per-client bound and pass a test that
	// only asked for the floor.
	if held != entitledFloor {
		t.Fatalf("the victim settled at %d sessions across %d holders, want exactly the %d it is entitled to keep", held, holders, entitledFloor)
	}
}

// TestSessionIdIsNeverOverwritten pins the same invariant addPending carries:
// an id already in the pool cannot be taken again, which would charge one
// client for a session another holds.
func TestSessionIdIsNeverOverwritten(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)

	if err := srv.addSession("client:first", "shared-id", establishedSession{lastUsed: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := srv.addSession("client:second", "shared-id", establishedSession{lastUsed: time.Now()}); err == nil {
		t.Fatal("a second client took a session id already in the pool")
	}

	srv.mu.Lock()
	held := len(srv.sessions)
	second := srv.sessionsBy.count("client:second")
	srv.mu.Unlock()
	if held != 1 {
		t.Fatalf("pool holds %d sessions, want 1", held)
	}
	if second != 0 {
		t.Fatalf("the refused client is charged %d sessions, want 0", second)
	}
}

// TestReadyzIsCached pins what bounds a flood on the readiness gate: the
// answer is computed at most once per TTL, however many callers ask. The gate
// stays unmetered because the kubelet probe shares the front door with them.
func TestReadyzIsCached(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             testFixture(),
		ExpectedWorkload:     "some-workload",
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	handler := srv.Handler()

	probe := func(remoteAddr, clientIP string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		req.RemoteAddr = remoteAddr
		if clientIP != "" {
			req.Header.Set("X-Real-IP", clientIP)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code, strings.TrimSpace(w.Body.String())
	}

	// The leaf carries no matched-workload stamp, so the gate withholds.
	code, reason := probe("127.0.0.1:5555", "203.0.113.7")
	if code != http.StatusServiceUnavailable || reason == "" {
		t.Fatalf("readiness with an unstamped leaf: got %d %q, want 503 with a reason", code, reason)
	}

	// Break the credential the check reads. Inside the TTL the cached answer
	// stands, which is what makes a flood cost one identity load per second.
	if err := os.WriteFile(identity.certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if _, cached := probe("127.0.0.1:5555", "198.51.100.9"); cached != reason {
			t.Fatalf("readiness recomputed inside its TTL on request %d: reason %q became %q", i, reason, cached)
		}
	}
	// A literal: readiness that a caller must wait longer than this for is
	// stale enough to act on wrongly, whatever the constant says.
	const staleAfter = 1500 * time.Millisecond
	time.Sleep(staleAfter)
	if _, fresh := probe("127.0.0.1:5555", "198.51.100.9"); fresh == reason {
		t.Fatalf("readiness was not recomputed within %v: still %q", staleAfter, reason)
	}

	// However hard the public path is driven, the probe still answers: the
	// gate is not metered, so a flood cannot deschedule the pod.
	for i := 0; i < 1000; i++ {
		probe("127.0.0.1:5555", "192.0.2.50")
	}
	if code, _ := probe("127.0.0.1:5555", "10.42.0.1"); code == http.StatusTooManyRequests {
		t.Fatal("the kubelet probe was refused after a flood on the public path")
	}
}

// TestTunnelIsCappedPerClientAcrossSessions pins the aggregate: a client
// holding many sessions cannot multiply its way past the client budget.
func TestTunnelIsCappedPerClientAcrossSessions(t *testing.T) {
	// Generous per session, tight per client: the aggregate must bind.
	_, ts, _ := newTestServerWith(t, func(srv *Server) {
		srv.sessionLimiter = newLimiter(0.001, 1000, clientBuckets)
		srv.clientLimiter = newLimiter(0.001, 4, clientBuckets)
	})

	channel, sessionID := establishSession(t, ts.URL, testNonce(t))
	var limited int
	for i := 0; i < 12; i++ {
		if tunnelStatus(t, ts.URL, sessionID, channel, i) == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 8 {
		t.Fatalf("%d of 12 tunnel requests were limited, want 8 past a client burst of 4", limited)
	}
}

// TestHandshakeRefusesWhenTheClientIsAtItsBound drives the session bound
// through the endpoint: a handshake whose session cannot be stored must not
// answer 200 with an id for a session the server does not hold.
func TestHandshakeRefusesWhenTheClientIsAtItsBound(t *testing.T) {
	srv, ts, _ := newMeteredTestServer(t)

	// The bucket a request through the front door is charged to.
	const client = "client:203.0.113.7"
	for i := 0; i < maxSessionsPerClient; i++ {
		if err := srv.addSession(client, fmt.Sprintf("held-%d", i), establishedSession{lastUsed: time.Now()}); err != nil {
			t.Fatalf("filling the client to its bound: %v", err)
		}
	}

	nonce := testNonce(t)
	bundle := fetchBundleAs(t, ts.URL, "203.0.113.7", nonce)
	_, handshake := clientChannelFromBundle(t, bundle, nonce)
	body, err := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(handshake.ClientX25519),
		MLKEMCt:      b64url(handshake.MLKEMCiphertext),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/handshake", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Real-IP", "203.0.113.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("handshake at the client's session bound: got %d, want 429", resp.StatusCode)
	}
	var refusal types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&refusal); err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	if refusal.Error != types.ErrorCodeTooManyRequests {
		t.Fatalf("refusal code = %q, want %q", refusal.Error, types.ErrorCodeTooManyRequests)
	}

	srv.mu.Lock()
	held := srv.sessionsBy.count(client)
	srv.mu.Unlock()
	if held != maxSessionsPerClient {
		t.Fatalf("client holds %d sessions after the refusal, want %d", held, maxSessionsPerClient)
	}
}

// fetchBundleAs fetches attest-pq as a named client.
func fetchBundleAs(t *testing.T, base, clientIP string, nonce []byte) types.AttestationBundle {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/.well-known/c8s/attest-pq?nonce="+b64url(nonce), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Real-IP", clientIP)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attest-pq status %d", resp.StatusCode)
	}
	var bundle types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	return bundle
}

// TestClientBucketFallsBackToTheAddress pins that per-client state is charged
// to something even when no front door named the client: without the fallback
// every direct caller shares one bound under the empty key.
func TestClientBucketFallsBackToTheAddress(t *testing.T) {
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "203.0.113.7:5555"
	if got := clientBucket(direct); got != "addr:203.0.113.7" {
		t.Fatalf("clientBucket for a direct caller = %q, want its address", got)
	}
	other := httptest.NewRequest(http.MethodGet, "/", nil)
	other.RemoteAddr = "198.51.100.9:5555"
	if got := clientBucket(other); got == clientBucket(direct) {
		t.Fatalf("two direct callers share the bucket %q", got)
	}
	front := httptest.NewRequest(http.MethodGet, "/", nil)
	front.RemoteAddr = "127.0.0.1:5555"
	front.Header.Set("X-Real-IP", "203.0.113.7")
	if got := clientBucket(front); got != "client:203.0.113.7" {
		t.Fatalf("clientBucket behind the front door = %q", got)
	}
}

// TestTunnelClientAggregateIsCheckedFirst pins the order of the two limiters
// on the tunnel: the per-client one carries no store lookup, so a request it
// refuses must never reach the lock that keying on a session takes.
func TestTunnelClientAggregateIsCheckedFirst(t *testing.T) {
	srv, ts, _ := newTestServerWith(t, func(srv *Server) {
		srv.clientLimiter = newLimiter(0.001, 0, clientBuckets) // refuses everything
	})

	// Hold the store lock: a request that reaches it will block until the
	// test releases it, and the refusal must not.
	srv.mu.Lock()
	defer srv.mu.Unlock()

	refused := make(chan int, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader([]byte("junk")))
		if err != nil {
			refused <- 0
			return
		}
		req.Header.Set("X-Real-IP", "203.0.113.7")
		req.Header.Set(sessionHeader, "any-session")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			refused <- 0
			return
		}
		defer resp.Body.Close()
		refused <- resp.StatusCode
	}()

	select {
	case code := <-refused:
		if code != http.StatusTooManyRequests {
			t.Fatalf("tunnel refused by the client aggregate: got %d, want 429", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a tunnel request refused by the client aggregate blocked on the store lock")
	}
}

// TestNonceTTLDefaultsShorterThanTheSession pins the wait a client is given
// between attest-pq and its handshake, which is the window a parked ML-KEM key
// is held for.
func TestNonceTTLDefaultsShorterThanTheSession(t *testing.T) {
	srv := NewServer(Config{Evidence: testFixture(), SessionTTL: time.Hour})
	if srv.cfg.NonceTTL != defaultNonceTTL {
		t.Fatalf("NonceTTL = %v, want %v", srv.cfg.NonceTTL, defaultNonceTTL)
	}
	if srv.cfg.NonceTTL >= srv.cfg.SessionTTL {
		t.Fatalf("NonceTTL %v is not shorter than SessionTTL %v", srv.cfg.NonceTTL, srv.cfg.SessionTTL)
	}
	// A handshake later than that window is refused even though the session
	// TTL has not passed.
	if err := srv.addPending("client:x", "aged", pendingSession{createdAt: time.Now().Add(-defaultNonceTTL - time.Second)}); err != nil {
		t.Fatal(err)
	}
	entry, ok := srv.takePending("aged")
	if !ok {
		t.Fatal("the parked handshake vanished")
	}
	if time.Since(entry.createdAt) <= srv.cfg.NonceTTL {
		t.Fatal("the parked handshake is still inside its TTL")
	}
}

// TestSweepReleasesExpiredEntries pins that the background sweep, which is the
// only sweep now, frees both the entry and the client's accounting.
func TestSweepReleasesExpiredEntries(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	const client = "client:203.0.113.7"

	stale := time.Now().Add(-2 * srv.cfg.SessionTTL)
	if err := srv.addPending(client, "expired", pendingSession{createdAt: stale}); err != nil {
		t.Fatal(err)
	}
	if err := srv.addSession(client, "idle", establishedSession{lastUsed: stale}); err != nil {
		t.Fatal(err)
	}
	if err := srv.addPending(client, "fresh", pendingSession{createdAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	srv.sweep()

	srv.mu.Lock()
	pending, sessions := len(srv.pending), len(srv.sessions)
	pendingHeld, sessionsHeld := srv.pendingBy.count(client), srv.sessionsBy.count(client)
	srv.mu.Unlock()
	if pending != 1 || pendingHeld != 1 {
		t.Fatalf("sweep left %d pending entries counted %d, want 1 of each", pending, pendingHeld)
	}
	if sessions != 0 || sessionsHeld != 0 {
		t.Fatalf("sweep left %d sessions counted %d, want none", sessions, sessionsHeld)
	}
}

// TestMaintainSweepsAndStopsWithItsContext pins the background loop: it is the
// only thing that reclaims expired entries now that no request sweeps, and it
// has to stop with its context.
func TestMaintainSweepsAndStopsWithItsContext(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	srv.sweepEvery = 5 * time.Millisecond

	if err := srv.addPending("client:x", "stale", pendingSession{createdAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.maintain(ctx)
		close(done)
	}()

	waitFor(t, "the expired handshake to be swept", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return len(srv.pending) == 0
	})

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("maintain did not return when its context was cancelled")
	}
}

// TestServeRunsMaintenance pins the wiring rather than the method: a sidecar
// that serves must also be sweeping, or expired entries sit until their store
// fills.
func TestServeRunsMaintenance(t *testing.T) {
	srv, _, _ := newMeteredTestServer(t)
	srv.sweepEvery = 5 * time.Millisecond

	if err := srv.addPending("client:x", "stale", pendingSession{createdAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, &http.Server{Addr: "127.0.0.1:0", Handler: srv.Handler()}) }()

	waitFor(t, "the expired handshake to be swept while serving", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return len(srv.pending) == 0
	})

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return when its context was cancelled")
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// tunnelStatus sends one sealed request over an established session.
func tunnelStatus(t *testing.T, base, sessionID string, ch *overenc.Channel, seq int) int {
	t.Helper()
	resp := postSealedTunnel(t, base, ch, sessionID, types.TunnelRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("/echo/%d", seq),
	})
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
