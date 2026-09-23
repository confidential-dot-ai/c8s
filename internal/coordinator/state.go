package coordinator

import (
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// State signs the current statement: the active policy, the outstanding update
// if there is one, and the journal head they were read at. Together they bound
// what may be executing in the attested participants.
//
// It is built and signed on demand. A cached copy proves which statement an
// ingress used, never that the statement is current — that is what Challenge is
// for.
func (c *Coordinator) State() (policystate.SignedState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signState()
}

// Challenge answers a verifier's nonce with the current statement and a second
// signature binding it to that nonce.
func (c *Coordinator) Challenge(nonce []byte) (policystate.ChallengedState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	signed, err := c.signState()
	if err != nil {
		return policystate.ChallengedState{}, err
	}
	return policystate.SignChallenge(c.signingKey, signed, nonce)
}

// signState builds and signs the statement. Callers hold c.mu.
func (c *Coordinator) signState() (policystate.SignedState, error) {
	version, digest, err := c.active()
	if err != nil {
		return policystate.SignedState{}, err
	}
	statement := policystate.State{
		Protocol:      policystate.Protocol,
		DeploymentID:  c.deploymentID,
		Authority:     c.authority,
		LogHead:       c.headDigest,
		LogPosition:   c.position(),
		ActiveVersion: version,
		ActiveDigest:  digest,
		Update:        c.outstanding(),
		IssuedAt:      c.now().UTC().Format(time.RFC3339),
	}
	return policystate.SignState(c.signingKey, statement)
}

// outstanding copies the update mirror, so a statement handed to a caller can
// never alias the coordinator's own state.
func (c *Coordinator) outstanding() *policystate.Update {
	if c.update == nil {
		return nil
	}
	u := *c.update
	return &u
}
