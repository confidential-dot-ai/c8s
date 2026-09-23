// Package policystateclient is the HTTP client for the CDS publication and
// state endpoints under /.well-known/c8s (pkg/policystate).
//
// Every object it fetches by digest is re-hashed before it is returned, so a
// caller never sees bytes that do not match the name it asked for. Signatures
// are not checked here: which authority to trust is the caller's decision.
package policystateclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// requestTimeout bounds one CDS call when the caller supplies no http.Client.
const requestTimeout = 30 * time.Second

// Response caps. Objects hold whole allowlists; everything else is small.
const (
	maxObjectBytes   = 4 * 1024 * 1024
	maxResponseBytes = 1 * 1024 * 1024
)

// Client talks to one CDS (or a proxy in front of it).
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New returns a client for baseURL with a default timeout.
func New(baseURL string) Client {
	return NewWithHTTP(baseURL, &http.Client{Timeout: requestTimeout})
}

// NewWithHTTP returns a client that sends through httpClient, which is how a
// caller supplies its RA-TLS-pinned transport.
func NewWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}
}

// Latest returns the publication head.
func (c Client) Latest(ctx context.Context) (policystate.Head, error) {
	var head policystate.Head
	err := c.getJSON(ctx, policystate.PathLatest, maxResponseBytes, &head)
	return head, err
}

// Object fetches the exact bytes of a content-addressed object and checks that
// they hash to digest.
func (c Client) Object(ctx context.Context, digest string) ([]byte, error) {
	sum, err := policystate.ParseHash(digest)
	if err != nil {
		return nil, err
	}
	hexDigest := digest[len("sha256:"):]
	body, err := c.get(ctx, policystate.PathObjectPrefix+hexDigest, maxObjectBytes)
	if err != nil {
		return nil, err
	}
	if got := policystate.ContentDigest(body); got != policystate.FormatHash(sum) {
		return nil, fmt.Errorf("object %s: served bytes hash to %s", digest, got)
	}
	return body, nil
}

// Policy fetches a policy object and checks that it parses as an allowlist. It
// returns the exact bytes, not the parse: a verifier pins these bytes, and a
// re-serialized document is a different object.
func (c Client) Policy(ctx context.Context, digest string) ([]byte, error) {
	body, err := c.Object(ctx, digest)
	if err != nil {
		return nil, err
	}
	if _, err := allowlist.ParseJSON(body); err != nil {
		return nil, fmt.Errorf("policy %s: %w", digest, err)
	}
	return body, nil
}

// Entry fetches one journal entry by digest and validates it.
func (c Client) Entry(ctx context.Context, digest string) (policystate.Entry, error) {
	body, err := c.Object(ctx, digest)
	if err != nil {
		return policystate.Entry{}, err
	}
	var entry policystate.Entry
	if err := policystate.Decode(body, &entry); err != nil {
		return policystate.Entry{}, fmt.Errorf("entry %s: %w", digest, err)
	}
	if err := policystate.ValidateEntry(entry); err != nil {
		return policystate.Entry{}, fmt.Errorf("entry %s: %w", digest, err)
	}
	return entry, nil
}

// State fetches the latest signed state statement. It is not verified: use
// policystate.VerifySignedState and decide whether to trust the authority it
// names.
func (c Client) State(ctx context.Context) (policystate.SignedState, error) {
	var s policystate.SignedState
	err := c.getJSON(ctx, policystate.PathState, maxResponseBytes, &s)
	return s, err
}

// Challenge posts nonce and returns the challenge-bound state. It is not
// verified: use policystate.VerifyChallengedState with the same nonce.
func (c Client) Challenge(ctx context.Context, nonce []byte) (policystate.ChallengedState, error) {
	if len(nonce) < policystate.MinNonceLen || len(nonce) > policystate.MaxNonceLen {
		return policystate.ChallengedState{}, fmt.Errorf("challenge: nonce is %d bytes, want %d..%d", len(nonce), policystate.MinNonceLen, policystate.MaxNonceLen)
	}
	req := policystate.ChallengeRequest{Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
	var cs policystate.ChallengedState
	err := c.postJSON(ctx, policystate.PathChallenge, req, &cs)
	return cs, err
}

// Enroll signs and posts an enrollment.
func (c Client) Enroll(ctx context.Context, bootKey ed25519.PrivateKey, e policystate.Enrollment) error {
	return c.postSigned(ctx, policystate.PathEnroll, bootKey, e)
}

// Ack signs and posts an update acknowledgement.
func (c Client) Ack(ctx context.Context, bootKey ed25519.PrivateKey, a policystate.Ack) error {
	return c.postSigned(ctx, policystate.PathAck, bootKey, a)
}

// Complete signs and posts a completion.
func (c Client) Complete(ctx context.Context, bootKey ed25519.PrivateKey, cp policystate.Completion) error {
	return c.postSigned(ctx, policystate.PathComplete, bootKey, cp)
}

func (c Client) postSigned(ctx context.Context, path string, key ed25519.PrivateKey, msg any) error {
	env, err := policystate.SignMessage(key, policystate.DomainAck, msg)
	if err != nil {
		return err
	}
	return c.postJSON(ctx, path, env, nil)
}

func (c Client) getJSON(ctx context.Context, path string, maxBytes int64, out any) error {
	body, err := c.get(ctx, path, maxBytes)
	if err != nil {
		return err
	}
	if err := policystate.Decode(body, out); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	return nil
}

func (c Client) get(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req, maxBytes)
}

// postJSON sends body as JSON and decodes the response into out when out is
// non-nil. A 2xx with out nil is success regardless of the body.
func (c Client) postJSON(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req, maxResponseBytes)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := policystate.Decode(resp, out); err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	return nil
}

func (c Client) do(req *http.Request, maxBytes int64) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := readutil.ReadAll(resp.Body, maxBytes)
	if errors.Is(err, readutil.ErrTooLarge) {
		return nil, fmt.Errorf("%s %s: response exceeds %d bytes", req.Method, req.URL.Path, maxBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: read response: %w", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &StatusError{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// StatusError is a non-2xx response. Callers switch on Status to tell a
// conflict (409: an update is outstanding, a boot key mismatch) from a
// rejection (401/422) or an unknown object (404).
type StatusError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("%s %s: server returned %d: %s", e.Method, e.Path, e.Status, e.Body)
	}
	return fmt.Sprintf("%s %s: server returned %d", e.Method, e.Path, e.Status)
}

// IsStatus reports whether err is a StatusError with the given status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == status
}
