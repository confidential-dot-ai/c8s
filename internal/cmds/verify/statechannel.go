package verify

import (
	"fmt"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
)

// stateNonceBytes is the challenge length the verifier sends CDS. It is the
// same 32 bytes the attestation endpoints take, and well inside policystate's
// 16..64 bound.
const stateNonceBytes = 32

// stateChannel reaches the CDS read endpoints, which the router publishes on
// the same origin as its attestation endpoint.
//
// Nothing fetched here is trusted for having come from this channel: objects
// are content-addressed and re-hashed, journal entries are chained, and the
// challenge is signed. The one exception is the authority fingerprint, which
// [authorityTrust] learns here only when bound is true — or not at all, in
// favour of --authority or a checkpoint.
type stateChannel struct {
	client policystateclient.Client
	// bound is true when the transport refuses any peer but the certificate
	// the evidence attests.
	bound bool
}

// newStateChannel builds the channel for one run, or an error explaining why
// there is none (a saved-file target has no origin to call).
func newStateChannel(cfg config, ev *evidence) (*stateChannel, error) {
	if cfg.url == "" {
		return nil, fmt.Errorf("this evidence source is a saved file, not a live endpoint")
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return nil, err
	}
	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		// Redirects would take the request off the origin whose certificate
		// the evidence attests.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   pinnedLeafTLS(cfg.server, ev.stateFetchCert),
		},
	}
	return &stateChannel{
		client: policystateclient.NewWithHTTP(baseURL, client),
		bound:  ev.stateFetchCert != "",
	}, nil
}
