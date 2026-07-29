package secrets

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Route is the path prefix the handler serves. The trailing wildcard is
// required: a store path has slashes in it, and a single-segment pattern would
// only ever match a top-level path.
const Route = "/secrets/*"

// authScheme prefixes the sandbox token in the Authorization header. The token
// travels in a header rather than the URL so it is covered by the server's
// header bound and never reaches a request log.
const authScheme = "SandboxToken "

// challengeSource issues and consumes the single-use nonces that make a request
// fresh. The secrets listener holds its own, so a nonce minted for issuance
// cannot be redeemed here.
type challengeSource interface {
	Consume(challenge []byte) bool
}

// inventorySource is the callback to a node's admission inventory: its
// sandbox-token signing key, and what a sandbox has run.
type inventorySource interface {
	InventoryKey(ctx context.Context, host string) (*ecdsa.PublicKey, error)
	FetchSandbox(ctx context.Context, host, sandboxID string) (workloadclaims.SandboxDigestsResponse, error)
}

// bindingSource resolves which inventory this process is willing to believe
// about a sandbox.
type bindingSource interface {
	Lookup(sandboxID string) (host string, ok bool)
}

// policySource supplies the current allowlist.
type policySource interface {
	Allowlist() (*pkgallowlist.Allowlist, error)
}

// Handler serves GET and POST on Route.
type Handler struct {
	Store      Store
	Challenges challengeSource
	Inventory  inventorySource
	Bindings   bindingSource
	Policy     policySource

	// InventoryHosts bounds the addresses the callback may dial. Empty refuses
	// every request: without it a workload could name its own pod.
	InventoryHosts workloadclaims.InventoryHosts

	// InjectedDigests are the images the platform injects into every
	// confidential pod. Containers running one are not part of a workload's
	// declared set, so they are dropped before matching.
	//
	// It is a set, not a single digest, for two reasons: the injected
	// containers need not all share an image, and an image bump changes the
	// digest while pods created before it keep running the old one. A CDS that
	// knew only the current digest would find an undroppable container in every
	// older pod and refuse it a secret until it was recreated, so both digests
	// belong here for the length of an upgrade.
	//
	// InjectedArgv0 are the entrypoints those images are injected with. A
	// container must match a digest AND an entrypoint to be dropped: these
	// images are argv-unconstrained allowlist floor entries, so dropping on the
	// digest alone would let a pod add a container running one of them as
	// anything at all and have it ignored.
	InjectedDigests []string
	InjectedArgv0   []string

	Logger *slog.Logger
}

// denial is a refusal to release. The reason reaches the CDS log; the client is
// told only that it was refused, because the detail describes the state of a
// pod the caller may not be entitled to learn about.
type denial struct {
	status int
	reason string
}

func (d denial) Error() string { return d.reason }

func deny(reason string, args ...any) denial {
	return denial{status: http.StatusForbidden, reason: fmt.Sprintf(reason, args...)}
}

func (h Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	path, err := requestPath(r)
	if err != nil {
		http.Error(w, "invalid secret path", http.StatusBadRequest)
		return
	}

	// The challenge is consumed unconditionally and first, exactly as issuance
	// does: a nonce that survives an early error path is a nonce that can be
	// replayed against another path.
	nonce, err := h.consumeChallenge(r)
	if err != nil {
		h.logger().Warn("secret request rejected", "path", path, "error", err)
		http.Error(w, "invalid or expired challenge", http.StatusBadRequest)
		return
	}

	grant, err := h.authorize(ctx, r, nonce)
	if err != nil {
		var d denial
		if !errors.As(err, &d) {
			d = denial{status: http.StatusForbidden, reason: err.Error()}
		}
		h.logger().Warn("secret request denied", "path", path, "reason", d.reason)
		http.Error(w, "not authorized for this secret", d.status)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.serveGet(ctx, w, grant, path)
	case http.MethodPost:
		h.servePost(ctx, w, grant, path)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h Handler) serveGet(ctx context.Context, w http.ResponseWriter, grant *pkgallowlist.SecretsPolicy, path string) {
	if !grant.Allows(path, pkgallowlist.OpRead) {
		// Indistinguishable from a path that does not exist: telling a caller
		// which of its ungranted guesses are real would enumerate the store.
		h.logger().Warn("secret read denied", "path", path)
		http.Error(w, "no such secret", http.StatusNotFound)
		return
	}
	value, err := h.Store.Get(ctx, path)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "no such secret", http.StatusNotFound)
			return
		}
		h.logger().Error("secret read failed", "path", path, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	writeValue(w, value, http.StatusOK)
}

func (h Handler) servePost(ctx context.Context, w http.ResponseWriter, grant *pkgallowlist.SecretsPolicy, path string) {
	if !grant.Allows(path, pkgallowlist.OpWrite) {
		h.logger().Warn("secret create denied", "path", path)
		http.Error(w, "no such secret", http.StatusNotFound)
		return
	}
	// The value is minted here and never supplied by the caller, so no client
	// chooses what another client will later read.
	candidate, err := Generate()
	if err != nil {
		h.logger().Error("generate secret failed", "path", path, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	_, created, err := h.Store.PutIfAbsent(ctx, path, candidate)
	if err != nil {
		h.logger().Error("secret create failed", "path", path, "error", err)
		http.Error(w, "secret unavailable", http.StatusInternalServerError)
		return
	}
	if !created {
		// The existing value is withheld: returning it here would make a write
		// grant a read grant. A caller that also holds read re-reads with GET,
		// which is how the replica that loses this race recovers.
		w.WriteHeader(http.StatusConflict)
		return
	}
	writeValue(w, candidate, http.StatusCreated)
}

// valueResponse carries a secret value. Base64 because a generated value is raw
// bytes.
type valueResponse struct {
	Value string `json:"value"`
}

func writeValue(w http.ResponseWriter, value []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(valueResponse{Value: base64.StdEncoding.EncodeToString(value)})
}

// requestPath returns the canonical store path a request names.
//
// It reads the escaped form and refuses anything not already canonical rather
// than repairing it, so the bytes matched against a grant, and the bytes used as
// a store key, are the bytes the client sent. Chi routes on the raw or the
// decoded path depending on whether the URL contained escapes, so deriving from
// one source and rejecting "%" removes that difference.
func requestPath(r *http.Request) (string, error) {
	raw := r.URL.EscapedPath()
	rest, ok := strings.CutPrefix(raw, "/secrets")
	if !ok {
		return "", fmt.Errorf("path %q is not under /secrets", raw)
	}
	return pkgallowlist.CanonicalSecretPath(rest)
}

func (h Handler) consumeChallenge(r *http.Request) ([]byte, error) {
	if h.Challenges == nil {
		return nil, fmt.Errorf("no challenge store configured")
	}
	raw := r.Header.Get("X-C8s-Challenge")
	if raw == "" {
		return nil, fmt.Errorf("missing challenge")
	}
	nonce, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("challenge is not base64")
	}
	if !h.Challenges.Consume(nonce) {
		return nil, fmt.Errorf("challenge is unknown, expired, or already used")
	}
	return nonce, nil
}

// authorize establishes which workload is calling and returns the secret grant
// that workload holds. Every failure is fail-closed.
func (h Handler) authorize(ctx context.Context, r *http.Request, nonce []byte) (*pkgallowlist.SecretsPolicy, error) {
	leaf, err := verifiedLeaf(r)
	if err != nil {
		return nil, deny("%v", err)
	}
	sandboxID, err := ratls.SandboxIDFromCert(leaf)
	if err != nil || sandboxID == "" {
		return nil, deny("client certificate carries no sandbox ID")
	}

	// The token re-proves, against this request's own challenge, that the
	// caller is still in that sandbox, and names the inventory that says so.
	token, err := h.parseToken(r)
	if err != nil {
		return nil, deny("%v", err)
	}
	host, err := h.verifyToken(ctx, token, leaf.PublicKey, nonce, sandboxID)
	if err != nil {
		return nil, deny("%v", err)
	}

	containers, err := h.runningContainers(ctx, host, sandboxID)
	if err != nil {
		return nil, deny("%v", err)
	}

	al, err := h.Policy.Allowlist()
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}
	name, workload, err := al.MatchWorkload(containers)
	if err != nil {
		return nil, deny("sandbox %s: %v", sandboxID, err)
	}
	if workload.Secrets == nil {
		return nil, deny("workload %q holds no secret grant", name)
	}
	return workload.Secrets, nil
}

// verifiedLeaf returns the client certificate, requiring that crypto/tls
// verified it against the configured roots. VerifiedChains is empty unless the
// listener both asked for a certificate and had roots to check it against, so
// this refuses a listener misconfigured to accept a self-signed peer — whose
// sandbox-ID extension would be whatever it chose.
func verifiedLeaf(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate")
	}
	if len(r.TLS.VerifiedChains) == 0 {
		return nil, fmt.Errorf("client certificate was not verified against the mesh CA")
	}
	return r.TLS.PeerCertificates[0], nil
}

func (h Handler) parseToken(r *http.Request) (*workloadclaims.SignedSandboxToken, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), authScheme)
	if !ok || raw == "" {
		return nil, fmt.Errorf("missing sandbox token")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("sandbox token is not base64")
	}
	var token workloadclaims.SignedSandboxToken
	dec := json.NewDecoder(bytes.NewReader(der))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&token); err != nil {
		return nil, fmt.Errorf("decode sandbox token: %w", err)
	}
	return &token, nil
}

// verifyToken checks the token against the inventory this process already
// believes owns the sandbox, and returns that inventory's host.
func (h Handler) verifyToken(ctx context.Context, token *workloadclaims.SignedSandboxToken, requesterPub crypto.PublicKey, nonce []byte, sandboxID string) (string, error) {
	if h.Inventory == nil || h.Bindings == nil {
		return "", fmt.Errorf("secrets are not configured to reach an inventory")
	}
	if len(h.InventoryHosts) == 0 {
		return "", fmt.Errorf("no inventory CIDRs are configured to bound the callback")
	}
	// The binding, not the token, decides who is asked. The token names a host
	// too, but that is the requester's choice; taking it would let anything able
	// to answer on the inventory port vouch for someone else's sandbox.
	host, ok := h.Bindings.Lookup(sandboxID)
	if !ok {
		return "", fmt.Errorf("no inventory is bound to sandbox %s", sandboxID)
	}
	if !h.InventoryHosts.Contains(host) {
		return "", fmt.Errorf("bound inventory is outside the configured node CIDRs")
	}
	claimed, err := workloadclaims.UnverifiedInventoryHost(token.Token)
	if err != nil {
		return "", err
	}
	if claimed != host {
		return "", fmt.Errorf("sandbox token names an inventory other than the one bound to this sandbox")
	}
	key, err := h.Inventory.InventoryKey(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve inventory key: %w", err)
	}
	verified, err := token.Verify(key, requesterPub, nonce)
	if err != nil {
		return "", err
	}
	if verified.SandboxID != sandboxID {
		return "", fmt.Errorf("sandbox token names a different sandbox than the certificate")
	}
	return host, nil
}

// runningContainers asks the bound inventory what the sandbox has run, and
// drops the platform's own injected containers so a workload entry need not
// enumerate them.
func (h Handler) runningContainers(ctx context.Context, host, sandboxID string) ([]pkgallowlist.RunningContainer, error) {
	resp, err := h.Inventory.FetchSandbox(ctx, host, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox containers: %w", err)
	}
	reported, err := resp.RequireContainers()
	if err != nil {
		return nil, err
	}
	out := make([]pkgallowlist.RunningContainer, 0, len(reported))
	for _, c := range reported {
		if h.isInjected(c) {
			continue
		}
		out = append(out, pkgallowlist.RunningContainer{Digest: c.Digest, Argv: c.Argv})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sandbox %s reports no workload containers", sandboxID)
	}
	return out, nil
}

// isInjected reports whether a reported container is one the platform injected.
// Both the image and the entrypoint must match — see InjectedDigests.
func (h Handler) isInjected(c workloadclaims.SandboxContainer) bool {
	if len(c.Argv) == 0 || !slices.Contains(h.InjectedDigests, c.Digest) {
		return false
	}
	return slices.Contains(h.InjectedArgv0, c.Argv[0])
}
