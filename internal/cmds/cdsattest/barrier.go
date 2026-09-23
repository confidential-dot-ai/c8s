package cdsattest

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// covers reports whether every digest of bound is in envelope: the rule that
// decides whether a session continues. A session is pinned to the envelope it
// was established under, so a later state narrows within it (the drain that
// ends an update) without costing the client a round trip, and a state that
// steps outside it retires the session.
func covers(envelope, bound []string) bool {
	for _, digest := range bound {
		if !slices.Contains(envelope, digest) {
			return false
		}
	}
	return true
}

// idleCloser is a backend that pools connections to the upstream. Retiring a
// session closes the client's channel but leaves the pooled connection its
// plaintext rode; the barrier has to take that too.
type idleCloser interface {
	CloseIdleConnections()
}

var (
	errNoSession    = errors.New("no over-encryption session")
	errStateChanged = errors.New("the deployment's policy bound moved outside this session's envelope; re-attest and review the new state")
)

// rebind installs the deployment's current bound and retires every session
// whose envelope does not cover it, returning how many it retired.
//
// It is the whole of the ingress barrier: it returns only once the retired
// sessions' in-flight tunnel requests have been cancelled and have returned,
// and once the pooled backend connections their plaintext rode are closed. An
// acknowledgement sent after it therefore covers operations that have stopped,
// not entries removed from a map.
func (s *Server) rebind(bound []string) int {
	s.mu.Lock()
	s.bound = bound
	var draining []chan struct{}
	retired := 0
	for id, sess := range s.sessions {
		if covers(sess.envelope, bound) {
			continue
		}
		retired++
		if done := s.retireSession(id); done != nil {
			draining = append(draining, done)
		}
	}
	s.mu.Unlock()
	for _, done := range draining {
		<-done
	}
	if retired > 0 {
		s.closeIdleBackendConns()
	}
	return retired
}

// retireSession drops one session and cancels the tunnel requests still using
// its channel, returning the channel closed when the last of them returns, or
// nil when there are none. Callers hold s.mu and must not wait on the result
// while holding it: the requests need the lock to finish.
func (s *Server) retireSession(id string) chan struct{} {
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	s.dropSession(id)
	for _, cancel := range sess.cancels {
		cancel()
	}
	if sess.inflight == 0 {
		return nil
	}
	sess.drained = make(chan struct{})
	return sess.drained
}

// setBound installs the bound without retiring anything. It is how the first
// verified statement arms the session checks before any session exists.
func (s *Server) setBound(bound []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bound = bound
}

func (s *Server) closeIdleBackendConns() {
	if closer, ok := s.backend.(idleCloser); ok {
		closer.CloseIdleConnections()
	}
}

// admitTunnel reports whether tunnel traffic may be carried at all, writing
// the refusal when it may not. It runs before the record is decrypted, and
// before the session lookup: a router that cannot say what policy the
// deployment is under must not forward plaintext under it.
//
// The session survives a stale statement: the router lost sight of CDS, the
// policy did not change, and the client's next attempt may well be served.
func (s *Server) admitTunnel(w http.ResponseWriter) bool {
	if _, err := s.verifiedState(); err != nil {
		s.log.Warn("refusing tunnel traffic on CDS state this front door cannot stand behind",
			"error", err, "state_max_age_seconds", s.cfg.StateMaxAge.Seconds())
		s.refuseState(w, err)
		return false
	}
	return true
}

// beginTunnel checks the session against the deployment's current bound and
// enrols this request in its in-flight accounting. The returned function ends
// that accounting and must run before the handler returns; cancel is called
// when the session is retired under the request.
//
// The bound check lives here rather than beside the other admission checks
// because it is the same critical section as the lookup: a session retired
// between the two would otherwise hand out a channel the barrier has already
// counted as gone.
func (s *Server) beginTunnel(id string, cancel context.CancelFunc) (*sessionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, errNoSession
	}
	now := time.Now()
	// Use refreshes the idle deadline but never the absolute one, so no amount
	// of traffic keeps one key schedule alive past SessionMaxAge.
	if now.Sub(sess.lastUsed) > s.cfg.SessionTTL || now.Sub(sess.createdAt) > s.cfg.SessionMaxAge {
		s.dropSession(id)
		return nil, errNoSession
	}
	if !covers(sess.envelope, s.bound) {
		s.dropSession(id)
		return nil, errStateChanged
	}
	sess.lastUsed = now
	req := sess.nextRequest
	sess.nextRequest++
	sess.cancels[req] = cancel
	sess.inflight++
	return &sessionRequest{server: s, session: sess, id: req}, nil
}

// sessionRequest is one tunnel request's claim on a session's channel.
type sessionRequest struct {
	server  *Server
	session *establishedSession
	id      uint64
}

// end releases the claim, releasing a barrier waiting on this session when it
// was the last request holding it.
func (r *sessionRequest) end() {
	s := r.server
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(r.session.cancels, r.id)
	r.session.inflight--
	if r.session.inflight == 0 && r.session.drained != nil {
		close(r.session.drained)
		r.session.drained = nil
	}
}

// refuseTunnel maps a refused tunnel request onto the wire. The two codes are
// different moves for the client: one re-attests from scratch, the other
// re-attests *and* reviews a policy bound it has not seen.
func (s *Server) refuseTunnel(w http.ResponseWriter, err error) {
	if errors.Is(err, errStateChanged) {
		writeErr(w, http.StatusConflict, types.ErrorCodeStateChanged, err.Error())
		return
	}
	writeErr(w, http.StatusUnauthorized, types.ErrorCodeChannelError, err.Error())
}
