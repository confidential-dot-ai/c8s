package cdsattest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		envelope []string
		bound    []string
		want     bool
	}{
		{name: "same policy", envelope: []string{digestP}, bound: []string{digestP}, want: true},
		{name: "narrowed to the target", envelope: []string{digestP, digestQ}, bound: []string{digestQ}, want: true},
		{name: "narrowed to the source", envelope: []string{digestP, digestQ}, bound: []string{digestP}, want: true},
		{name: "widened past the envelope", envelope: []string{digestP}, bound: []string{digestP, digestQ}, want: false},
		{name: "moved to another policy", envelope: []string{digestP}, bound: []string{digestQ}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := covers(tc.envelope, tc.bound); got != tc.want {
				t.Fatalf("covers(%v, %v) = %v, want %v", tc.envelope, tc.bound, got, tc.want)
			}
		})
	}
}

// participantCDS records what the ingress posts to the private coordinator
// API. It verifies each envelope under the enrolled boot key, so a test fails
// on an unsigned or wrongly signed message rather than counting it.
type participantCDS struct {
	t *testing.T

	mu           sync.Mutex
	enrollments  []policystate.Enrollment
	acks         []policystate.Ack
	completions  []policystate.Completion
	refuseEnroll int
}

func (c *participantCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch r.URL.Path {
	case policystate.PathEnroll:
		if c.refuseEnroll != 0 {
			w.WriteHeader(c.refuseEnroll)
			return
		}
		var env policystate.Envelope[policystate.Enrollment]
		c.decode(w, r, &env)
		c.enrollments = append(c.enrollments, env.Message)
	case policystate.PathAck:
		var env policystate.Envelope[policystate.Ack]
		c.decode(w, r, &env)
		c.acks = append(c.acks, env.Message)
	case policystate.PathComplete:
		var env policystate.Envelope[policystate.Completion]
		c.decode(w, r, &env)
		c.completions = append(c.completions, env.Message)
	default:
		http.NotFound(w, r)
	}
}

func (c *participantCDS) decode(_ http.ResponseWriter, r *http.Request, out any) {
	c.t.Helper()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		c.t.Errorf("decode %s: %v", r.URL.Path, err)
	}
}

func (c *participantCDS) snapshot() ([]policystate.Enrollment, []policystate.Ack, []policystate.Completion) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.enrollments), slices.Clone(c.acks), slices.Clone(c.completions)
}

// newParticipant wires the update driver to a server and a recording CDS.
func newParticipant(t *testing.T, srv *Server) (*updateDriver, *participantCDS) {
	t.Helper()
	cds := &participantCDS{t: t}
	ts := httptest.NewServer(cds)
	t.Cleanup(ts.Close)
	boot, err := newBootIdentity("router-test")
	if err != nil {
		t.Fatal(err)
	}
	return newUpdateDriver(policystateclient.New(ts.URL), srv, boot, quietLogger()), cds
}

// establish runs one attest-pq exchange against a state-bound front door and
// returns the client's channel, the session id and the envelope the response
// committed.
func establishBound(t *testing.T, base string) (*overenc.Channel, string, []string) {
	t.Helper()
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := testNonce(t)
	bundle := fetchBundle(t, base, ck, nonce)
	channel, id := clientChannelFromBundle(t, bundle, ck, nonce)
	return channel, id, bundle.Envelope
}

// A session pinned to the source alone is retired when a publication widens
// the bound to source-or-target, and the acknowledgement that follows counts
// it: the request that was inside the tunnel when the barrier ran is cancelled
// and has returned before the ack is posted.
func TestSourceOnlySessionIsRetiredBeforeTheAck(t *testing.T) {
	f := newStateFixture(t)
	// A backend that parks the request until the test releases it, so the
	// barrier genuinely has an in-flight operation to wait for.
	entered, release := make(chan struct{}), make(chan struct{})
	blocking := backendFunc(func(ctx context.Context, _ types.TunnelRequest) (types.TunnelResponse, error) {
		close(entered)
		select {
		case <-release:
			return types.TunnelResponse{Status: http.StatusOK}, nil
		case <-ctx.Done():
			return types.TunnelResponse{}, ctx.Err()
		}
	})
	srv, ts, _ := newStateBoundServer(t, f.state)
	srv.backend = blocking
	driver, cds := newParticipant(t, srv)
	driver.onState(context.Background(), f.settled(1, digestP))

	channel, id, envelope := establishBound(t, ts.URL)
	if !slices.Equal(envelope, []string{digestP}) {
		t.Fatalf("envelope = %v, want the source alone", envelope)
	}

	inflight := make(chan *http.Response, 1)
	go func() {
		inflight <- postSealedTunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"})
	}()
	<-entered

	// The publication widens the bound past this session's envelope.
	f.install(f.publishing(2, false))
	barrierDone := make(chan struct{})
	go func() {
		driver.onState(context.Background(), f.publishing(2, false))
		close(barrierDone)
	}()

	select {
	case <-barrierDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the barrier did not return: it is not cancelling the in-flight tunnel request")
	}
	close(release)
	resp := <-inflight
	resp.Body.Close()

	_, acks, _ := cds.snapshot()
	if len(acks) != 1 {
		t.Fatalf("acks = %d, want exactly one for the outstanding update", len(acks))
	}
	if acks[0].Retired != 1 || acks[0].Version != 2 || acks[0].TargetDigest != digestQ {
		t.Fatalf("ack = %+v, want one retired session for version 2 targeting %s", acks[0], digestQ)
	}
	if got := srv.sessionCount(); got != 0 {
		t.Fatalf("sessions = %d, want the source-only session gone", got)
	}
}

// A session established while the update is outstanding carries both digests,
// so neither the switch nor the drain that follows retires it.
func TestPreapprovedSessionSurvivesTheSwitchAndTheDrain(t *testing.T) {
	f := newStateFixture(t)
	f.install(f.publishing(2, false))
	srv, ts, _ := newStateBoundServer(t, f.state)
	driver, cds := newParticipant(t, srv)
	ctx := context.Background()
	driver.onState(ctx, f.publishing(2, false))

	channel, id, envelope := establishBound(t, ts.URL)
	want := []string{digestP, digestQ}
	slices.Sort(want)
	if !slices.Equal(envelope, want) {
		t.Fatalf("envelope = %v, want the source-or-target bound %v", envelope, want)
	}

	// Switch: the target is in force, the bound still covers both.
	f.install(f.publishing(3, true))
	driver.onState(ctx, f.publishing(3, true))
	if resp := tunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"}); resp.Status != http.StatusOK {
		t.Fatalf("tunnel after the switch = %d, want 200", resp.Status)
	}

	// Drained: the update is gone and the bound narrows to the target, which
	// the envelope still covers.
	f.install(f.settled(4, digestQ))
	driver.onState(ctx, f.settled(4, digestQ))
	if resp := tunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"}); resp.Status != http.StatusOK {
		t.Fatalf("tunnel after the drain = %d, want 200", resp.Status)
	}

	_, acks, completions := cds.snapshot()
	if len(acks) != 1 || acks[0].Retired != 0 {
		t.Fatalf("acks = %+v, want one acknowledgement retiring nothing", acks)
	}
	if len(completions) != 1 || completions[0].Version != 2 {
		t.Fatalf("completions = %+v, want one for version 2", completions)
	}
}

// Enrollments, acknowledgements and drain reports move the log head without
// changing what may be executing. A session must not die for them.
func TestLogHeadOnlyChangeKeepsSessions(t *testing.T) {
	f := newStateFixture(t)
	srv, ts, _ := newStateBoundServer(t, f.state)
	driver, _ := newParticipant(t, srv)
	ctx := context.Background()
	driver.onState(ctx, f.settled(1, digestP))

	channel, id, _ := establishBound(t, ts.URL)
	f.install(f.settled(9, digestP))
	driver.onState(ctx, f.settled(9, digestP))

	if got := srv.sessionCount(); got != 1 {
		t.Fatalf("sessions = %d, want the session kept across a log-head move", got)
	}
	if resp := tunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"}); resp.Status != http.StatusOK {
		t.Fatalf("tunnel after a log-head move = %d, want 200", resp.Status)
	}
}

// The router lost sight of CDS: it refuses to carry traffic under state it can
// no longer vouch for, but the policy did not change, so the session stays and
// the next attempt is served.
func TestStaleStateRefusesTunnelAndKeepsTheSession(t *testing.T) {
	f := newStateFixture(t)
	srv, ts, _ := newStateBoundServer(t, f.state)
	channel, id, _ := establishBound(t, ts.URL)

	f.state.age(2 * time.Minute)
	resp := postSealedTunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("tunnel on stale state = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if code := errorCode(t, resp); code != types.ErrorCodeStateStale {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeStateStale)
	}
	if got := srv.sessionCount(); got != 1 {
		t.Fatalf("sessions = %d, want the session kept: the policy did not change", got)
	}

	f.install(f.settled(1, digestP))
	if resp := tunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"}); resp.Status != http.StatusOK {
		t.Fatalf("tunnel once CDS is reachable again = %d, want 200", resp.Status)
	}
}

// A session whose envelope the bound has left answers state_changed once and
// is gone: the client re-attests and reviews the policy it would now run under.
func TestTunnelRefusesASessionOutsideTheBound(t *testing.T) {
	f := newStateFixture(t)
	srv, ts, _ := newStateBoundServer(t, f.state)
	channel, id, _ := establishBound(t, ts.URL)

	srv.setBound([]string{digestQ})
	resp := postSealedTunnel(t, ts.URL, channel, id, types.TunnelRequest{Method: "GET", Path: "/"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("tunnel outside the envelope = %d, want %d", resp.StatusCode, http.StatusConflict)
	}
	if code := errorCode(t, resp); code != types.ErrorCodeStateChanged {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeStateChanged)
	}
	if got := srv.sessionCount(); got != 0 {
		t.Fatalf("sessions = %d, want the session dropped", got)
	}
}

// CDS holds a joining participant outside an outstanding update. The 409 is
// the expected answer, and the ingress enrols on a later poll.
func TestEnrollmentRetriesAfterAConflict(t *testing.T) {
	f := newStateFixture(t)
	srv, _, _ := newStateBoundServer(t, f.state)
	driver, cds := newParticipant(t, srv)
	ctx := context.Background()

	cds.refuseEnroll = http.StatusConflict
	driver.onState(ctx, f.publishing(2, false))
	if enrollments, _, _ := cds.snapshot(); len(enrollments) != 0 {
		t.Fatalf("enrollments = %+v, want none while CDS refuses", enrollments)
	}
	if driver.enrolled {
		t.Fatal("the driver counts itself enrolled after a 409")
	}

	cds.refuseEnroll = 0
	driver.onState(ctx, f.settled(3, digestP))
	enrollments, _, _ := cds.snapshot()
	if len(enrollments) != 1 || enrollments[0].AppliedDigest != digestP {
		t.Fatalf("enrollments = %+v, want one naming the active policy", enrollments)
	}
}

// backendFunc adapts a function to the Backend interface.
type backendFunc func(context.Context, types.TunnelRequest) (types.TunnelResponse, error)

func (f backendFunc) Forward(ctx context.Context, req types.TunnelRequest) (types.TunnelResponse, error) {
	return f(ctx, req)
}
