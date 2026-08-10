package workloadclaims

import "sync"

// Signer availability, as the token route reports it.
//
// Under kata the inventory listener must bind before the guest has a network:
// containers share the guest's netns, so a listener bound after the workload
// starts is one the workload can bind first and answer as. The signing key,
// though, names the address CDS dials back on, which is only knowable once the
// pod network exists. The route therefore outlives its own signer, and these
// are the three answers it can give.
type signerState int

const (
	// signerPending is "ask again": the address the signer commits to is not
	// resolvable yet. Answered 503, retried by the caller.
	signerPending signerState = iota

	// signerReady is a usable signer.
	signerReady

	// signerUnsupported is "stop asking": this deployment issues no sandbox
	// tokens at all. Answered 404, and the caller proceeds without a sandbox
	// ID — the long-standing node-CVM behaviour when no CDS is configured.
	signerUnsupported
)

// SignerHolder carries the sandbox-token signer for a listener that must serve
// before the signer exists. Safe for concurrent use.
type SignerHolder struct {
	mu     sync.RWMutex
	state  signerState
	signer *SandboxTokenSigner
}

// NewSignerHolder returns a holder that already knows its answer: signer when
// non-nil, otherwise "this deployment issues no tokens". For a caller that
// resolves its signer later, use NewPendingSignerHolder.
func NewSignerHolder(signer *SandboxTokenSigner) *SignerHolder {
	if signer == nil {
		return &SignerHolder{state: signerUnsupported}
	}
	return &SignerHolder{state: signerReady, signer: signer}
}

// NewPendingSignerHolder returns a holder whose signer arrives later. Until it
// does the route answers 503, so a caller waits rather than issuing a leaf with
// no sandbox ID — a binding CDS takes first-write-wins and will not revisit.
func NewPendingSignerHolder() *SignerHolder {
	return &SignerHolder{state: signerPending}
}

// Set installs the signer and makes the route answer.
func (h *SignerHolder) Set(signer *SandboxTokenSigner) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state, h.signer = signerReady, signer
}

// Disable records that no signer is coming, so callers stop waiting on one.
// For a failure waiting cannot fix — no CDS configured, measurements that do
// not parse — as distinct from a network that has not arrived yet.
func (h *SignerHolder) Disable() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state, h.signer = signerUnsupported, nil
}

// Ready reports whether a signer is installed, for the log line that tells an
// operator which posture a guest came up in.
func (h *SignerHolder) Ready() bool {
	_, state := h.current()
	return state == signerReady
}

func (h *SignerHolder) current() (*SandboxTokenSigner, signerState) {
	if h == nil {
		return nil, signerUnsupported
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.signer, h.state
}
