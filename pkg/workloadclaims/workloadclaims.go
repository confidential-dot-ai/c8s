// Package workloadclaims implements the admission-inventory API: the component
// that admitted a pod's containers (nri-image-policy on node-CVM,
// policy-monitor in a kata guest) is the arbiter of both what runs in a pod
// sandbox and which sandbox a process belongs to.
//
// It serves two disjoint surfaces (docs/ratls.md, "Sandbox identity"):
//
//   - a node-local token route, where get-cert redeems its identity for a
//     signed sandbox token naming its own sandbox — nothing the caller sends
//     names the pod. On node-CVM that is a Unix socket, whose kernel peer
//     credentials bind the caller; inside a kata guest it is guest loopback,
//     where the single-pod guest boundary does;
//   - a network endpoint over mutually-attested RA-TLS, where CDS asks which
//     image digests a named sandbox is currently running.
//
// Keeping them apart bounds each: the socket cannot enumerate other sandboxes,
// and the network endpoint cannot mint identity.
package workloadclaims

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// SandboxPath is the token route on the local Unix socket; SandboxDigestsPrefix
// is the digests route on the CDS-facing network endpoint. POST SandboxPath
// issues a signed sandbox token for the calling process (caller bound by kernel
// peer credentials; see sandboxtoken.go). GET SandboxDigestsPrefix+<sandboxID>
// lists the tracked container image digests of that sandbox.
const (
	SandboxPath          = "/sandbox"
	SandboxDigestsPrefix = "/digests/"
	IdentityPath         = "/identity"
)

// InventoryIdentity is the IdentityPath answer: the inventory's sandbox-token
// signing key, PKIX DER. Served on the same privileged-port listener as the
// digests, which is what makes it an identity rather than an assertion.
type InventoryIdentity struct {
	PublicKey []byte `json:"public_key"`
}

// SocketName is the fixed filename of the inventory's Unix socket, and
// SidecarSocketDir is where the socket directory is presented inside the
// c8s-cert sidecar. Both are compiled constants, not deployment values:
// get-cert dials InventoryEndpoint (built from them) as a baked path, so the
// control plane cannot redirect the fetch to a rogue inventory
// (docs/getcert-workload-binding.md Corner 5). The inventory (nri-image-policy on
// node-CVM, policy-monitor in the kata guest) creates its socket as SocketName
// under its configured directory, and the webhook hostPath-mounts that
// directory at SidecarSocketDir in the pod. node-CVM only: a kata guest serves
// the token route on loopback instead (GuestTokenPort), with nothing to mount.
const (
	SocketName       = "workload-claims.sock"
	SidecarSocketDir = "/run/c8s/workload-claims"
)

// GuestTokenPort is the in-guest loopback port policy-monitor serves the token
// route on under kata, alongside the attestation-service on 8400. A kata guest
// holds exactly one pod and its containers share the guest's network namespace,
// so loopback reaches the inventory without a shared filesystem — the same
// transport the in-guest attestation-service already uses. Peer credentials are
// not needed there: with one pod per guest there is no caller to disambiguate.
const GuestTokenPort = 8401

// InventoryEndpoint is get-cert's compiled inventory endpoint on node-CVM: the
// in-sidecar Unix socket path, whose peer credentials bind the caller to its
// pod.
func InventoryEndpoint() string {
	return "unix://" + SidecarSocketDir + "/" + SocketName
}

// GuestInventoryEndpoint is get-cert's compiled inventory endpoint inside a kata
// guest. Like InventoryEndpoint it is fixed at build time: the control plane
// selects which of the two shapes applies, never an address, so the worst a
// wrong selection does is fail closed against a port nothing serves.
func GuestInventoryEndpoint() string {
	return "http://127.0.0.1:" + strconv.Itoa(GuestTokenPort)
}

// InventorySocketGID owns the inventory's Unix socket. The inventory runs as root, but
// get-cert connects as the non-root c8s UID/GID over a read-only mount; a
// root:root 0660 socket is unreachable by that caller (connect needs write
// permission on the socket node), so the connect would fail closed and issuance
// would hang. The inventory chgrps the socket to this group and the webhook
// injects it as a supplemental group on the get-cert sidecar
// (pod_mutator.go, ensureSupplementalGroup) — together they let the non-root
// caller connect. Reuses the c8s distroless nonroot GID, so a default get-cert
// (RunAsGroup 65532) also reaches it via its primary group. Connecting to a
// socket is exempt from the read-only-mount write block (sockets are not
// regular files), so the RO mount still prevents a socket-file swap without
// blocking the connect.
const InventorySocketGID = 65532

// ListenUnix binds an inventory's Unix socket at socketPath: it removes a stale
// socket file first (so an inventory restart does not fail with EADDRINUSE), chmods
// the socket to 0660, and (when gid > 0) chgrps it to gid so a non-root caller
// in that group can connect. Caller binding is by kernel peer credentials, so
// the mode and group gate reachability only, not authorization.
func ListenUnix(socketPath string, gid int) (net.Listener, error) {
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod %s: %w", socketPath, err)
	}
	if gid > 0 {
		if err := os.Chown(socketPath, -1, gid); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("chgrp %s to gid %d: %w", socketPath, gid, err)
		}
	}
	return l, nil
}

// maxResponseBytes bounds an inventory response; a pod has a handful of
// containers, each digest 71 bytes.
const maxResponseBytes = 1 << 20

// SandboxTokenRequest is the SandboxPath request body: the requester's PKIX
// public-key DER, which the inventory binds into the signed token so only the
// holder of that key can redeem it at CDS.
type SandboxTokenRequest struct {
	PublicKey []byte `json:"public_key"`
	// Nonce is the single-use CDS challenge get-cert obtained for this
	// issuance. The inventory binds it into the signed token so CDS confirms
	// freshness against the same challenge it consumes for the evidence — no
	// clock (docs/ratls.md, "Sandbox identity").
	Nonce []byte `json:"nonce"`
}

// SandboxDigestsResponse is the SandboxDigestsPrefix answer. Both fields
// describe every container ever admitted in the sandbox, not only those running
// now — see docs/secrets.md, "The report is a high-water mark".
//
// Digests is the deduplicated digest set cert issuance gates on. Containers
// carries each container's effective argv and is not deduplicated, so a consumer
// can hold a sandbox to the same (digest, argv) pair admission evaluated.
//
// Digests is [] (never null) for a known sandbox with no containers. Containers
// is absent on an inventory that predates it, which consumers must treat as
// "cannot answer" rather than "no containers".
type SandboxDigestsResponse struct {
	Digests    []string           `json:"digests"`
	Containers []SandboxContainer `json:"containers,omitempty"`
	// AllowlistRefresh is the inventory's enforcement posture. Absent from an
	// inventory that predates the field, and from one with nothing to report.
	AllowlistRefresh *AllowlistRefresh `json:"allowlist_refresh,omitempty"`
}

// AllowlistRefresh reports whether an inventory's image allowlist still tracks
// CDS, or has fallen back to whatever it started with. It is the one channel
// carrying that state out of a kata guest, whose journal the operator cannot
// read — kubectl logs on locked-guest pods is empty.
//
// Diagnostic only: no issuance or release decision reads it, so a guest cannot
// widen its own admission by lying here.
type AllowlistRefresh struct {
	Enabled bool `json:"enabled"`
	// Reason explains a disabled refresh.
	Reason string `json:"reason,omitempty"`
	// Entries is the allowlist size actually being enforced.
	Entries int `json:"entries"`
}

// AllowlistRefreshReporter is the optional half of SandboxResolver: an
// inventory that can describe its refresh posture. ok=false means it has
// nothing to report, which stays off the wire rather than serializing as a
// disabled refresh.
type AllowlistRefreshReporter interface {
	AllowlistRefresh() (AllowlistRefresh, bool)
}

// SandboxContainer is one admitted container: the bytes, and what they were
// told to run.
type SandboxContainer struct {
	Digest string `json:"digest"`
	// Argv is the effective OCI process.args — the merged image-config and
	// pod-spec command, which is what the argv policy is written against.
	Argv []string `json:"argv,omitempty"`
}

// SandboxResolver is the surface an inventory implements — nri-image-policy on
// node-CVM (runtime sandbox state from NRI pod events) and policy-monitor in
// the kata guest (the guest's single pod). ServeTokens uses SandboxForPeer;
// ServeDigests uses DigestsForSandbox. get-cert treats a missing SandboxPath
// as "no sandbox ID" (ErrSandboxUnsupported).
//
// peer carries the kernel-pinned caller identity (SO_PEERCRED PID plus an
// SO_PEERPIDFD liveness pin) — the caller never names its own pod. The
// node-CVM resolver binds peer.PID() to a pod and rechecks peer.IsAlive()
// after its /proc read to reject PID reuse; the kata resolver ignores it,
// since the guest holds exactly one pod and no disambiguation is needed.
type SandboxResolver interface {
	// SandboxForPeer returns the pod sandbox ID of the calling process,
	// bound by kernel peer credentials exactly like ContainersForPeer.
	SandboxForPeer(peer Peer) (string, error)
	// DigestsForSandbox returns every container ever admitted in the named
	// sandbox — deduplicated digests for issuance, and the per-container
	// (digest, argv) detail for secret release. known=false means no such
	// sandbox (a 404 on the wire); a known sandbox with no containers returns
	// empty slices.
	DigestsForSandbox(sandboxID string) (digests []string, containers []SandboxContainer, known bool, err error)
}

// connKey carries the accepted net.Conn through the request context so the
// handler can read kernel peer credentials from it.
type connKey struct{}

// peerFromRequest pins the caller of an inventory request. The returned Peer's
// pidfd must be released with Close once resolution is done.
func peerFromRequest(r *http.Request) Peer {
	conn, _ := r.Context().Value(connKey{}).(net.Conn)
	return peerFrom(conn)
}

// PeerFromConn captures the peer credentials of a unix connection, for a server
// outside this package that binds its callers the same way. Exported so that
// server does not reimplement SO_PEERCRED; the returned Peer's pidfd must be
// released with Close.
func PeerFromConn(c net.Conn) Peer { return peerFrom(c) }

// maxSandboxRequestBytes bounds a SandboxPath request body; it carries one
// PKIX public key.
const maxSandboxRequestBytes = 64 << 10

// ServeTokens runs the token route on l until ctx is done — a unix listener on
// node-CVM, a guest-loopback listener under kata. It serves POST SandboxPath
// only, and l must stay node- or guest-local: on the socket the caller is bound
// by kernel peer credentials, and in the guest by the single-pod boundary.
// Errors from the resolver are returned as 500s — get-cert fails closed on them.
//
// A nil signer serves nothing (404 on the route): no signer means no CDS to
// attest the signing key against, and an unverifiable token is worse than none.
func ServeTokens(ctx context.Context, l net.Listener, resolver SandboxResolver, signer *SandboxTokenSigner) error {
	mux := http.NewServeMux()
	if signer != nil {
		mux.HandleFunc("POST "+SandboxPath, func(w http.ResponseWriter, r *http.Request) {
			var req SandboxTokenRequest
			if err := json.NewDecoder(io.LimitReader(r.Body, maxSandboxRequestBytes)).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("decode sandbox token request: %v", err), http.StatusBadRequest)
				return
			}
			pub, err := x509.ParsePKIXPublicKey(req.PublicKey)
			if err != nil {
				http.Error(w, fmt.Sprintf("parse requester key: %v", err), http.StatusBadRequest)
				return
			}
			keyDigest, err := RequesterKeyDigest(pub)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(req.Nonce) == 0 {
				http.Error(w, "missing challenge nonce", http.StatusBadRequest)
				return
			}
			peer := peerFromRequest(r)
			defer peer.Close()
			id, err := resolver.SandboxForPeer(peer)
			if err != nil {
				http.Error(w, fmt.Sprintf("resolve caller sandbox: %v", err), http.StatusInternalServerError)
				return
			}
			token, err := signer.Sign(id, keyDigest, req.Nonce)
			if err != nil {
				http.Error(w, fmt.Sprintf("sign sandbox token: %v", err), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(token)
		})
	}
	return serveUntil(ctx, l, mux)
}

// ServeDigests runs the CDS-facing digests endpoint on l until ctx is done. It
// serves GET SandboxDigestsPrefix+<sandboxID> only, and answers for ANY
// sandbox — so l MUST be a mutually-attested RA-TLS listener that admits only
// CDS (BuildDigestsTLSConfig). Over a plain listener this would disclose the
// node's running images to anyone who can reach the port.
func ServeDigests(ctx context.Context, l net.Listener, resolver SandboxResolver, identity []byte) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+IdentityPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(InventoryIdentity{PublicKey: identity})
	})
	mux.HandleFunc("GET "+SandboxDigestsPrefix+"{sandboxID}", func(w http.ResponseWriter, r *http.Request) {
		digests, containers, known, err := resolver.DigestsForSandbox(r.PathValue("sandboxID"))
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve sandbox digests: %v", err), http.StatusInternalServerError)
			return
		}
		if !known {
			http.Error(w, "unknown sandbox", http.StatusNotFound)
			return
		}
		if digests == nil {
			digests = []string{}
		}
		resp := SandboxDigestsResponse{Digests: digests, Containers: containers}
		if rr, ok := resolver.(AllowlistRefreshReporter); ok {
			if refresh, reported := rr.AllowlistRefresh(); reported {
				resp.AllowlistRefresh = &refresh
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return serveUntil(ctx, l, mux)
}

// serveUntil runs mux on l until ctx is done. The accepted net.Conn is carried
// through the request context so handlers can read kernel peer credentials
// from it (ServeTokens).
func serveUntil(ctx context.Context, l net.Listener, mux *http.ServeMux) error {
	// All four bounds are set explicitly: Go's defaults are infinite, and
	// ServeDigests runs this on a network listener reachable by anything that
	// can route to the node.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// inventoryDo performs a request against the inventory at endpoint, which must
// be one of the two compiled endpoints: the node-CVM unix socket (whose peer
// credentials bind the caller) or the kata guest's loopback address (where the
// guest boundary does). Anything else is refused, so no control-plane value can
// redirect the request (docs/getcert-workload-binding.md, Corner 5).
func inventoryDo(ctx context.Context, endpoint, method, route string, body io.Reader, timeout time.Duration) (*http.Response, error) {
	base := "http://inventory.invalid"
	transport := &http.Transport{}
	switch {
	case strings.HasPrefix(endpoint, "unix://"):
		path := strings.TrimPrefix(endpoint, "unix://")
		// Host placeholder — the dialer ignores it and connects to path.
		// .invalid is RFC 2606-reserved, so it can never resolve.
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
	case endpoint == GuestInventoryEndpoint():
		base = endpoint
	default:
		return nil, fmt.Errorf("workloadclaims: endpoint must be the compiled unix socket or guest loopback, got %q", endpoint)
	}
	// Fresh Transport, so Proxy stays nil: no HTTP_PROXY can interpose.
	client := &http.Client{Timeout: timeout, Transport: transport}

	req, err := http.NewRequestWithContext(ctx, method, base+route, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: fetch %s: %w", endpoint, err)
	}
	return resp, nil
}

// ErrSandboxUnsupported reports that the inventory serves no SandboxPath route —
// an inventory without sandbox state or without a CDS-attested signing key.
// Callers proceed without a sandbox ID.
var ErrSandboxUnsupported = errors.New("workloadclaims: inventory does not serve the sandbox route")

// FetchSandboxToken asks the inventory at endpoint for a signed sandbox token
// bound to requesterPub (the caller's CSR key) and nonce (the CDS challenge for
// this issuance, which CDS re-checks for freshness). A 404 maps to
// ErrSandboxUnsupported so callers can distinguish an inventory without the route
// from a resolution failure, which stays fail-closed.
func FetchSandboxToken(ctx context.Context, endpoint string, timeout time.Duration, requesterPub crypto.PublicKey, nonce []byte) (*SignedSandboxToken, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(requesterPub)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal requester key: %w", err)
	}
	body, err := json.Marshal(SandboxTokenRequest{PublicKey: pubDER, Nonce: nonce})
	if err != nil {
		return nil, err
	}
	resp, err := inventoryDo(ctx, endpoint, http.MethodPost, SandboxPath, bytes.NewReader(body), timeout)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSandboxUnsupported
	}
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("workloadclaims: inventory returned %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var out SignedSandboxToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("workloadclaims: decode inventory response: %w", err)
	}
	if len(out.Token) == 0 || len(out.Signature) == 0 {
		return nil, fmt.Errorf("workloadclaims: inventory returned an incomplete sandbox token")
	}
	return &out, nil
}
