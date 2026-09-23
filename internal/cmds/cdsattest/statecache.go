package cdsattest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// StateProvider supplies the CDS state statement attest-pq commits.
type StateProvider interface {
	// State returns the newest verified statement and when it was fetched.
	// ok is false until one has been verified.
	State() (signed policystate.SignedState, fetchedAt time.Time, ok bool)
}

// stateBinding is the policy an attest-pq response commits: the statement
// itself, the hash the transcript frames, the envelope the session is pinned
// to, and the route it is forwarded to. One value fills the transcript and the
// response fields together, so they can never disagree.
type stateBinding struct {
	raw      json.RawMessage
	hash     string
	envelope []string
	route    string
}

// fill adds the policy fields to an attest-pq bundle.
func (b *stateBinding) fill(bundle *types.AttestationBundle) {
	bundle.State, bundle.StateHash, bundle.Envelope, bundle.Route = b.raw, b.hash, b.envelope, b.route
}

// Why the front door cannot answer for the deployment's policy right now.
// The first is a deployment shape — this sidecar serves no protected traffic
// at all without CDS — and is a 501; the other two are transient and are
// state_stale, where the client's move is to retry.
var (
	errStateUnconfigured = errors.New("this front door has no CDS state source configured; attest-pq binds the deployment's policy state and there is no unbound mode")
	errStateUnverified   = errors.New("no CDS state statement has been verified yet; retry shortly")
	errStateTooOld       = errors.New("the last verified CDS state statement is older than this front door's maximum age")
)

// verifiedState returns the newest statement this front door can still stand
// behind. It gates the attestation binding and tunnel traffic alike: neither
// may proceed on state the router can no longer claim reflects CDS.
func (s *Server) verifiedState() (policystate.SignedState, error) {
	if s.cfg.State == nil {
		return policystate.SignedState{}, errStateUnconfigured
	}
	signed, fetchedAt, have := s.cfg.State.State()
	if !have {
		return policystate.SignedState{}, errStateUnverified
	}
	if age := time.Since(fetchedAt); age > s.cfg.StateMaxAge {
		return policystate.SignedState{}, fmt.Errorf("%w (%.0fs old)", errStateTooOld, age.Seconds())
	}
	return signed, nil
}

// refuseState writes the refusal for a state this front door cannot stand
// behind, telling a misconfiguration apart from an outage.
func (s *Server) refuseState(w http.ResponseWriter, err error) {
	if errors.Is(err, errStateUnconfigured) {
		writeErr(w, http.StatusNotImplemented, types.ErrorCodeBindingUnavailable, err.Error())
		return
	}
	writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeStateStale, err.Error())
}

// stateBinding resolves what an attest-pq response must commit, or writes the
// refusal and returns ok=false. It runs before any attestation is minted: a
// request the front door cannot bind costs no evidence.
func (s *Server) stateBinding(w http.ResponseWriter) (*stateBinding, bool) {
	signed, err := s.verifiedState()
	if err != nil {
		s.log.Warn("refusing an attestation on CDS state this front door cannot stand behind",
			"error", err, "state_max_age_seconds", s.cfg.StateMaxAge.Seconds())
		s.refuseState(w, err)
		return nil, false
	}
	hash, err := policystate.StateHash(signed.Statement)
	if err != nil {
		s.log.Error("hash CDS state", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "state binding failed")
		return nil, false
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		s.log.Error("encode CDS state", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "state binding failed")
		return nil, false
	}
	return &stateBinding{
		raw:      raw,
		hash:     hash,
		envelope: policystate.Bound(signed.Statement),
		route:    s.cfg.ExpectedWorkload,
	}, true
}

// stateCache polls CDS for its signed state statement and keeps the newest
// one that verified. It is a cache, not a buffer: a statement that fails
// verification never replaces the one held, and the server refuses to bind a
// held statement older than --state-max-age rather than serve it silently.
//
// The channel to CDS is RA-TLS-pinned, so the authority a first verified
// statement names is learned over a channel authenticated by CDS's
// measurement. A later change of authority is a CDS restart: the new key
// signs the statements that carry it, so the cache follows it and logs the
// change rather than holding a key no live CDS still has.
type stateCache struct {
	client  policystateclient.Client
	log     *slog.Logger
	refresh time.Duration
	now     func() time.Time
	// onState runs after every statement the cache accepts, on the poll
	// goroutine. It is the ingress side of the rollout protocol
	// (transition.go). Set it before Run; nothing reads it concurrently.
	onState func(context.Context, policystate.State)

	mu        sync.Mutex
	signed    policystate.SignedState
	fetchedAt time.Time
	ok        bool
}

// newStateCache returns a cache polling client every refresh.
func newStateCache(client policystateclient.Client, refresh time.Duration, logger *slog.Logger) *stateCache {
	if logger == nil {
		logger = slog.Default()
	}
	return &stateCache{client: client, log: logger, refresh: refresh, now: time.Now}
}

// State implements StateProvider.
func (c *stateCache) State() (policystate.SignedState, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signed, c.fetchedAt, c.ok
}

// Run polls until ctx is cancelled. It is how the cache stops: the server
// context owns the goroutine.
func (c *stateCache) Run(ctx context.Context) {
	c.refreshOnce(ctx)
	ticker := time.NewTicker(c.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshOnce(ctx)
		}
	}
}

// refreshOnce fetches and verifies one statement, logging and keeping the
// previous one on any failure.
func (c *stateCache) refreshOnce(ctx context.Context) {
	signed, err := c.client.State(ctx)
	if err != nil {
		c.log.Warn("fetch CDS state failed", "error", err)
		return
	}
	if err := policystate.VerifySignedState(signed); err != nil {
		c.log.Warn("CDS state did not verify; keeping the previous statement", "error", err)
		return
	}
	if !c.store(signed) || c.onState == nil {
		return
	}
	c.onState(ctx, signed.Statement)
}

// follow registers the driver the cache calls after each accepted statement.
func (c *stateCache) follow(fn func(context.Context, policystate.State)) {
	c.onState = fn
}

// store keeps a verified statement unless it rewinds the log under the
// authority it was already serving, and reports whether it kept it. A rewind
// is CDS restoring a snapshot or a second instance answering; binding it
// would let a verifier see an older bound as current.
func (c *stateCache) store(signed policystate.SignedState) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok {
		switch held := c.signed.Statement; {
		case held.Authority != signed.Statement.Authority:
			c.log.Warn("CDS state authority changed: a restarted CDS signs with a new key, and every verifier must re-anchor on it",
				"held", held.Authority, "served", signed.Statement.Authority)
		case signed.Statement.LogPosition < held.LogPosition:
			c.log.Warn("CDS log position went backwards; keeping the newer statement",
				"held", held.LogPosition, "served", signed.Statement.LogPosition)
			return false
		}
	}
	c.signed, c.fetchedAt, c.ok = signed, c.now(), true
	return true
}
