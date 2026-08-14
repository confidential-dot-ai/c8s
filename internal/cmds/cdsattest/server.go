// Package cdsattest implements the tls-lb attestation + over-encryption sidecar:
// the *dynamic* client-facing endpoints of the c8s-verify protocol. The
// tls-lb nginx front-end terminates public TLS, serves the static CDS/mesh-CA
// certs, and reverse-proxies the two explicit attestation endpoints
// (attest-pq, attest-lb), the handshake, and the over-encrypted application
// paths to this sidecar on loopback. attest-pq lets an out-of-cluster
// JavaScript client verify that the LB is a genuine, CDS-issued, TEE-attested
// endpoint and then talk to it over a post-quantum over-encrypted channel that
// terminates inside the LB's enclave — independent of whatever TLS terminator
// sits in front of it. attest-lb binds fresh evidence to the exact serving
// leaf for native clients that ride ordinary nginx TLS instead. See
// c8s-verify-js/PROTOCOL.md.
package cdsattest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/server"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const wellKnownPrefix = "/.well-known/c8s"

// nonceBytes is the exact client nonce length both attestation endpoints
// require: the transcripts frame a 32-byte nonce and anything else is refused
// rather than truncated or padded.
const nonceBytes = 32

// sessionHeader names the session a tunnel request rides.
const sessionHeader = "X-C8s-Session"

// Bounds on the unauthenticated endpoints: what one client may hold, and what
// the process holds across all of them.
const (
	// Session establishment: one attestation report and one ML-KEM keypair per
	// request, and a client needs two requests to open a session.
	establishRateLimit = 10 // requests per second per client
	establishRateBurst = 20
	// One established session's application traffic, charged to the session.
	sessionRateLimit = 200
	sessionRateBurst = 400
	// Tunnel traffic across all of a client's sessions, charged to the client
	// on top of its per-session budget.
	clientRateLimit = 400
	clientRateBurst = 800

	// A limiter refuses a key it has no bucket for once its map is full, so
	// the map size is the ceiling on how many callers it can meter at once.
	// clientBuckets covers the distinct clients a front door sees inside one
	// idle timeout; the session limiter also carries one bucket per live
	// session, so its map holds the whole session store on top of them.
	clientBuckets        = 1 << 16
	sessionBuckets       = maxSessions + clientBuckets
	limiterEvictInterval = time.Minute
	limiterIdleTimeout   = 5 * time.Minute

	// One client may hold a sixteenth of each store: a public address fronts
	// a whole CGNAT or corporate egress, so the per-client tier is sized for
	// the crowd behind one address. The global tier is the memory ceiling.
	maxPendingPerClient  = 512
	maxPendingSessions   = 8192
	maxSessionsPerClient = 512
	maxSessions          = 8192
	// minShare is the floor under a client's fair share of either store. It is
	// what stops an attacker setting the share by the number of addresses it
	// buys: below this many entries a client is never taken from, however many
	// clients hold the rest.
	minShare = 8

	// sweepInterval paces the background eviction of expired pending
	// handshakes and idle sessions. Both are also checked on use.
	sweepInterval = 10 * time.Second
	// shutdownGrace bounds the wait for in-flight requests at shutdown.
	shutdownGrace = 5 * time.Second
	// defaultNonceTTL bounds the wait between attest-pq and the handshake: a
	// client verifies the report in between, and nothing else.
	defaultNonceTTL = 30 * time.Second
	// readyzCacheTTL bounds how stale a readiness answer may be. The check
	// reads and parses the whole mesh identity, and the conditions it reports
	// change on the scale of a certificate renewal.
	readyzCacheTTL = time.Second
)

var (
	errNonceInUse   = errors.New("a handshake is already pending for this nonce")
	errSessionInUse = errors.New("a session already holds this id")
	errSessionsFull = errors.New("too many sessions are open for this client")
	errStoreFull    = errors.New("the server is at capacity; retry shortly")
)

// Front-door modes: which credential terminates the public TLS in front of
// this sidecar. attest-lb transport trust rests on the serving key being
// TEE-held, so it is served only in cds mode; a WebPKI Secret's key is
// host-visible and that deployment shape is attest-pq-only.
const (
	FrontDoorModeCDS    = "cds"
	FrontDoorModeWebPKI = "webpki"
)

// Backend handles a decrypted application request and returns the response. The
// sidecar seals the response back to the client. Implementations forward the
// reconstructed request to the real backend (see backend.go).
type Backend interface {
	Forward(ctx context.Context, req types.TunnelRequest) (types.TunnelResponse, error)
}

// Config configures the sidecar server.
type Config struct {
	Logger   *slog.Logger
	Evidence EvidenceProvider
	// FrontDoorMode says which credential terminates public TLS in front of
	// this sidecar (FrontDoorModeCDS or FrontDoorModeWebPKI). Anything but
	// cds — including an unset mode — refuses attest-lb, so a
	// misconfiguration can never serve a transport binding for a
	// host-visible key.
	FrontDoorMode string
	// ServingCertFile is the path to the LB serving-leaf PEM (the cert nginx
	// presents on the wire). In cds front-door mode, GET .../attest-lb binds
	// report_data to this exact leaf DER plus the mesh identity. Re-read per
	// request so a get-cert renewal (which SIGHUPs nginx to a new leaf) is
	// picked up without restarting the sidecar.
	ServingCertFile string
	// MeshIdentity* are the TEE-held mesh leaf, matching private key, and CA
	// bundle whose possession both attestation endpoints prove. They are
	// deliberately separate from ServingCertFile, which may name a
	// host-visible public TLS credential. All three files are re-read for
	// each attestation request.
	MeshIdentityCertFile string
	MeshIdentityKeyFile  string
	MeshIdentityCAFile   string
	// ExpectedWorkload gates /readyz on the installed mesh identity leaf
	// carrying a matched-workload stamp with this exact name. Empty keeps
	// /readyz unconditionally 200.
	ExpectedWorkload string
	Backend          Backend // over-encrypted application backend (nil => EchoBackend)
	SessionTTL       time.Duration
	// NonceTTL bounds how long a pending handshake nonce stays valid between
	// the attestation fetch and the handshake POST. Defaults to
	// defaultNonceTTL.
	NonceTTL time.Duration
}

type pendingSession struct {
	key        *overenc.ServerKey
	transcript []byte // identity transcript hash, the channel's HKDF salt
	createdAt  time.Time
	client     string // rate-limit bucket the entry is accounted to
}

type establishedSession struct {
	channel  *overenc.Channel
	lastUsed time.Time
	client   string
}

// Server serves the c8s-verify endpoints.
type Server struct {
	cfg     Config
	log     *slog.Logger
	backend Backend
	// establishLimiter meters attest-pq, attest-lb and the handshake per
	// client; sessionLimiter meters one session's tunnel traffic; and
	// clientLimiter is the per-client aggregate over every session a client
	// holds, plus readiness.
	establishLimiter *issuer.IPRateLimiter
	sessionLimiter   *issuer.IPRateLimiter
	clientLimiter    *issuer.IPRateLimiter

	mu         sync.Mutex
	pending    map[string]pendingSession     // nonce(b64url) -> server key
	pendingBy  *holders                      // client -> its nonces
	sessions   map[string]establishedSession // session id -> channel
	sessionsBy *holders                      // client -> its session ids

	sweepEvery time.Duration
	evictEvery time.Duration
	idleAfter  time.Duration

	readyzMu     sync.Mutex
	readyzAt     time.Time
	readyzCode   int
	readyzReason string
}

// NewServer constructs a Server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 5 * time.Minute
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = defaultNonceTTL
	}
	backend := cfg.Backend
	if backend == nil {
		backend = EchoBackend{}
	}
	return &Server{
		cfg:              cfg,
		log:              cfg.Logger,
		backend:          backend,
		establishLimiter: newLimiter(establishRateLimit, establishRateBurst, clientBuckets),
		sessionLimiter:   newLimiter(sessionRateLimit, sessionRateBurst, sessionBuckets),
		clientLimiter:    newLimiter(clientRateLimit, clientRateBurst, clientBuckets),
		sweepEvery:       sweepInterval,
		evictEvery:       limiterEvictInterval,
		idleAfter:        limiterIdleTimeout,
		pending:          make(map[string]pendingSession),
		pendingBy:        newHolders(),
		sessions:         make(map[string]establishedSession),
		sessionsBy:       newHolders(),
	}
}

func newLimiter(limit rate.Limit, burst, buckets int) *issuer.IPRateLimiter {
	limiter, err := issuer.NewIPRateLimiter(limit, burst, buckets)
	if err != nil {
		panic("cdsattest: " + err.Error())
	}
	return limiter
}

// Serve runs the sidecar until ctx is cancelled: the listener, its graceful
// shutdown, and the maintenance its stores need.
func (s *Server) Serve(ctx context.Context, httpSrv *http.Server) error {
	go cmdsutil.ShutdownOnDone(ctx, httpSrv, shutdownGrace)
	go s.maintain(ctx)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// maintain evicts expired pending handshakes, idle sessions and quiet
// rate-limiter entries. It blocks until ctx is cancelled.
func (s *Server) maintain(ctx context.Context) {
	for _, limiter := range []*issuer.IPRateLimiter{s.establishLimiter, s.sessionLimiter, s.clientLimiter} {
		go limiter.EvictionLoop(ctx, s.evictEvery, s.idleAfter)
	}
	ticker := time.NewTicker(s.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

// Handler returns the chi router for the LB endpoints.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Unmetered: the kubelet probes it through the same front door as the
	// public, so a per-client limit keyed on the address nginx records would
	// throttle the probe under externalTrafficPolicy: Cluster, which SNATs
	// every client onto the node. The cache below is what bounds a flood.
	r.Get("/readyz", s.handleReadyz)
	r.Method(http.MethodGet, wellKnownPrefix+"/attest-pq", s.establishing(http.HandlerFunc(s.handleAttestPQ)))
	r.Method(http.MethodGet, wellKnownPrefix+"/attest-lb", s.establishing(http.HandlerFunc(s.handleAttestLB)))
	// The pre-split endpoint. Kept registered so a stale client gets the
	// explicit versioned 400 — never a 404 it might treat as transient, and
	// never an alias or downgrade.
	r.Get(wellKnownPrefix+"/attestation", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest,
			"the /.well-known/c8s/attestation endpoint is gone: use attest-pq (encrypted session) or attest-lb (ordinary TLS)")
	})
	r.Method(http.MethodPost, wellKnownPrefix+"/handshake", s.establishing(http.HandlerFunc(s.handleHandshake)))
	// Over-encrypted application traffic: a single tunnel endpoint. The real
	// method/path/headers/body are sealed inside the request envelope, so nginx
	// only needs to route this one fixed path to the sidecar.
	r.Method(http.MethodPost, wellKnownPrefix+"/tunnel",
		s.perClient(issuer.RateLimitBy(s.sessionLimiter, s.tunnelKey, http.HandlerFunc(s.handleTunnel))))
	return r
}

// establishing rate-limits the session-establishment endpoints per client.
func (s *Server) establishing(next http.Handler) http.Handler {
	return issuer.RateLimitBy(s.establishLimiter, clientKey, next)
}

// perClient rate-limits on the client alone. It wraps the session limiter on
// the tunnel, so a request the client aggregate refuses never reaches the
// store lock that keying on a session needs.
func (s *Server) perClient(next http.Handler) http.Handler {
	return issuer.RateLimitBy(s.clientLimiter, clientKey, next)
}

// tunnelKey charges tunnel traffic to the session the sidecar issued. A
// request naming no live session is charged to its client, so a caller cannot
// name a bucket by inventing a session id.
func (s *Server) tunnelKey(r *http.Request) string {
	id := r.Header.Get(sessionHeader)
	if id == "" {
		return clientKey(r)
	}
	s.mu.Lock()
	_, live := s.sessions[id]
	s.mu.Unlock()
	if !live {
		return clientKey(r)
	}
	return "session:" + id
}

// clientKey charges a request to the address nginx recorded in X-Real-IP on
// the loopback hop. A request whose peer is not loopback did not come through
// the front door and is charged to its own address.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if peer := net.ParseIP(host); peer == nil || !peer.IsLoopback() {
		return ""
	}
	client := net.ParseIP(r.Header.Get("X-Real-IP"))
	if client == nil {
		return ""
	}
	return "client:" + issuer.ClientPrefix(client.String())
}

// clientBucket names the bucket a request's per-client state is counted in,
// falling back the same way the limiter does when there is no front door.
func clientBucket(r *http.Request) string {
	if key := clientKey(r); key != "" {
		return key
	}
	return issuer.SourceAddrKey(r)
}

// attestNonce validates the shared request shape of both attestation
// endpoints and returns the decoded nonce, or writes the 400 and returns nil.
// The endpoints take no binding or pq parameter: each serves exactly one
// binding, so there is nothing to negotiate, and a stale query-selecting
// client must get a loud 400, never something else than it expects.
func attestNonce(w http.ResponseWriter, r *http.Request) (nonceB64 string, nonce []byte) {
	q := r.URL.Query()
	// Presence, not value: `?pq=` is still a client that thinks it selects a
	// binding, and it must hear the 400 rather than be served silently.
	if q.Has("pq") {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "the pq query selector is gone: the endpoint path selects the binding")
		return "", nil
	}
	if q.Has("binding") {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "the attestation endpoints take no binding parameter")
		return "", nil
	}
	nonceB64 = q.Get("nonce")
	if nonceB64 == "" {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "missing nonce")
		return "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "nonce must be base64url")
		return "", nil
	}
	// Both transcripts frame an exact 32-byte client nonce; refuse anything
	// else rather than truncate or pad the freshness binding.
	if len(decoded) != nonceBytes {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, fmt.Sprintf("nonce must be %d bytes, got %d", nonceBytes, len(decoded)))
		return "", nil
	}
	return nonceB64, decoded
}

// handleAttestPQ serves the identity-bound over-encryption binding:
// report_data commits the hybrid session key, nonce, exact mesh leaf, and
// issuing mesh CA to one domain-separated transcript, and the leaf signs that
// transcript to prove possession of its private key.
func (s *Server) handleAttestPQ(w http.ResponseWriter, r *http.Request) {
	nonceB64, nonce := attestNonce(w, r)
	if nonce == nil {
		return
	}
	// Ahead of the report this request would mint: a request the store will
	// not take costs no attestation.
	client := clientBucket(r)
	if err := s.pendingRoom(client, nonceB64); err != nil {
		s.refusePending(w, err)
		return
	}
	if s.cfg.MeshIdentityCertFile == "" || s.cfg.MeshIdentityKeyFile == "" || s.cfg.MeshIdentityCAFile == "" {
		writeErr(w, http.StatusNotImplemented, types.ErrorCodeBindingUnavailable, "identity-bound PQ is not configured on this LB")
		return
	}
	identity, err := loadMeshIdentity(s.cfg.MeshIdentityCertFile, s.cfg.MeshIdentityKeyFile, s.cfg.MeshIdentityCAFile)
	if err != nil {
		s.log.Error("mesh identity binding unavailable", "error", err)
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable, "identity-bound PQ credentials are temporarily unavailable")
		return
	}

	key, err := overenc.GenerateServerKey()
	if err != nil {
		s.log.Error("generate session key", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "key generation failed")
		return
	}
	pub := key.Public()

	reportData, proof, err := identity.bind(pub, nonce)
	if err != nil {
		s.log.Error("bind mesh identity", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "mesh identity binding failed")
		return
	}

	evidence, platform, generation, err := s.cfg.Evidence.Evidence(r.Context(), reportData)
	if err != nil {
		s.log.Error("evidence provider failed", "error", err)
		writeErr(w, http.StatusBadGateway, types.ErrorCodeAttestationUnavailable, "could not obtain attestation evidence")
		return
	}

	if err := s.addPending(client, nonceB64, pendingSession{
		key:        key,
		transcript: append([]byte(nil), reportData...),
		createdAt:  time.Now(),
	}); err != nil {
		s.refusePending(w, err)
		return
	}

	writeJSON(w, http.StatusOK, types.AttestationBundle{
		Version:    types.BindingAttestPQ,
		Platform:   platform,
		Generation: generation,
		Nonce:      nonceB64,
		Evidence:   evidence,
		CDSCertPEM: string(identity.bundlePEM),
		SessionPubKey: &types.SessionPublicKey{
			X25519:   base64.RawURLEncoding.EncodeToString(pub.X25519),
			MLKEM768: base64.RawURLEncoding.EncodeToString(pub.MLKEM768),
		},
		IdentityProof: proof,
	})
}

// handleAttestLB serves the ordinary-TLS binding: report_data commits the
// nonce, the exact serving leaf nginx presents, the exact mesh leaf, and the
// issuing mesh CA (overenc.LBTranscriptHash), and the mesh leaf signs that
// transcript. No over-encryption keypair is minted and no pending session is
// stored — the client recomputes the transcript from the leaf it observed on
// its own TLS connection and then rides that TLS.
func (s *Server) handleAttestLB(w http.ResponseWriter, r *http.Request) {
	nonceB64, nonce := attestNonce(w, r)
	if nonce == nil {
		return
	}
	// The exact-DER binding detects leaf substitution, not key sharing: a
	// WebPKI Secret's serving key is host-visible, so the host could terminate
	// the client's TLS with the same leaf and proxy this request. Only a
	// TEE-held (cds-mode) serving key supports transport binding.
	if s.cfg.FrontDoorMode != FrontDoorModeCDS {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeUnsupportedFrontDoor,
			"attest-lb requires a TEE-held serving key (public_tls.mode=cds); this front door is attest-pq-only")
		return
	}
	servingLeafDER, err := s.servingLeafDER()
	if err != nil {
		s.log.Error("attest-lb binding unavailable", "error", err)
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable,
			"the serving certificate is unavailable; attest-lb cannot bind this connection")
		return
	}
	identity, err := loadMeshIdentity(s.cfg.MeshIdentityCertFile, s.cfg.MeshIdentityKeyFile, s.cfg.MeshIdentityCAFile)
	if err != nil {
		s.log.Error("mesh identity binding unavailable", "error", err)
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable, "mesh identity credentials are temporarily unavailable")
		return
	}

	reportData, proof, err := identity.bindServingLeaf(servingLeafDER, nonce)
	if err != nil {
		s.log.Error("bind serving leaf", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "serving-leaf binding failed")
		return
	}

	evidence, platform, generation, err := s.cfg.Evidence.Evidence(r.Context(), reportData)
	if err != nil {
		s.log.Error("evidence provider failed", "error", err)
		writeErr(w, http.StatusBadGateway, types.ErrorCodeAttestationUnavailable, "could not obtain attestation evidence")
		return
	}

	servingLeafHash := sha256.Sum256(servingLeafDER)
	writeJSON(w, http.StatusOK, types.AttestationBundle{
		Version:           types.BindingAttestLB,
		Platform:          platform,
		Generation:        generation,
		Nonce:             nonceB64,
		Evidence:          evidence,
		CDSCertPEM:        string(identity.bundlePEM),
		IdentityProof:     proof,
		ServingLeafSHA256: base64.RawURLEncoding.EncodeToString(servingLeafHash[:]),
	})
}

// servingLeafDER reads the LB serving-leaf PEM and returns the whole leaf DER.
// It is read per request so a get-cert renewal (which SIGHUPs nginx to a new
// leaf) is picked up without restarting the sidecar. Exactly one certificate
// is committed; per-SNI or multi-certificate serving is unsupported and fails
// the client's exact-DER comparison closed.
func (s *Server) servingLeafDER() ([]byte, error) {
	if s.cfg.ServingCertFile == "" {
		return nil, fmt.Errorf("no --serving-cert-file configured")
	}
	pemBytes, err := os.ReadFile(s.cfg.ServingCertFile)
	if err != nil {
		return nil, fmt.Errorf("read serving cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("serving cert %q is not a PEM certificate", s.cfg.ServingCertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse serving cert: %w", err)
	}
	return cert.Raw, nil
}

// handleReadyz gates readiness on the committed mesh identity, not the outer
// serving leaf: with --expected-workload set, ready means the whole credential
// the attestation endpoints would serve loads — leaf matching its private key,
// leaf and issuing CA both inside their validity windows, chain to a configured
// mesh CA — *and* that leaf carries a valid matched-workload stamp naming that
// workload. So ingress never routes external traffic to a front door whose
// committed identity is unusable or unnamed (initial deploy, or a post-foreign
// renewal). Absent, malformed, or duplicate stamps fail closed. Without the
// flag, today's always-ready behavior is kept.
//
// nginx proxies this endpoint from the public front door (location = /readyz),
// so the 503 body carries a reason that is not configuration and the specifics
// go to the log.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	code, reason := s.readiness()
	w.WriteHeader(code)
	if reason != "" {
		fmt.Fprintln(w, reason)
	}
}

// readiness answers from a result no older than readyzCacheTTL. Concurrent
// probes collapse onto one computation of it, so the cost of a flood is the
// cost of one check per TTL.
func (s *Server) readiness() (int, string) {
	s.readyzMu.Lock()
	defer s.readyzMu.Unlock()
	if !s.readyzAt.IsZero() && time.Since(s.readyzAt) < readyzCacheTTL {
		return s.readyzCode, s.readyzReason
	}
	s.readyzCode, s.readyzReason = s.computeReadiness()
	s.readyzAt = time.Now()
	return s.readyzCode, s.readyzReason
}

func (s *Server) computeReadiness() (int, string) {
	if s.cfg.ExpectedWorkload == "" {
		return http.StatusOK, ""
	}
	notReady := func(reason string, detail ...any) (int, string) {
		s.log.Warn("readiness gate withholding traffic", append([]any{"reason", reason}, detail...)...)
		return http.StatusServiceUnavailable, reason
	}
	// Exactly the load attest-pq/attest-lb do: reading and parsing the leaf
	// alone would report ready on a credential those endpoints refuse — an
	// expired leaf above all, which is what this gate exists to catch, since
	// stamped leaves carry a short TTL (issuer.MaxNamedLeafTTL).
	identity, err := loadMeshIdentity(s.cfg.MeshIdentityCertFile, s.cfg.MeshIdentityKeyFile, s.cfg.MeshIdentityCAFile)
	if err != nil {
		return notReady("mesh identity credentials unusable", "error", err)
	}
	workload, err := ratls.MatchedWorkloadFromCert(identity.leaf)
	switch {
	case err != nil:
		return notReady("matched-workload stamp malformed", "error", err)
	case workload == nil:
		return notReady("mesh identity leaf carries no matched-workload stamp")
	case workload.Name != s.cfg.ExpectedWorkload:
		// Both names are this front door's configuration and this body is
		// reachable from the public internet; name them only in the log.
		return notReady("mesh identity leaf is stamped for a different workload",
			"stamped", workload.Name, "expected", s.cfg.ExpectedWorkload)
	}
	return http.StatusOK, ""
}

func (s *Server) handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req types.HandshakeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "invalid JSON")
		return
	}

	now := time.Now()
	entry, ok := s.takePending(req.Nonce)
	if !ok || now.Sub(entry.createdAt) > s.cfg.NonceTTL {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "unknown or expired nonce")
		return
	}

	clientX, err1 := base64.RawURLEncoding.DecodeString(req.ClientX25519)
	ct, err2 := base64.RawURLEncoding.DecodeString(req.MLKEMCt)
	if err1 != nil || err2 != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "handshake fields must be base64url")
		return
	}

	handshake := overenc.Handshake{ClientX25519: clientX, MLKEMCiphertext: ct}
	channel, err := entry.key.Agree(handshake, entry.transcript)
	if err != nil {
		s.log.Warn("handshake agree failed", "error", err)
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "key agreement failed")
		return
	}

	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		s.log.Error("generate session id", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "session id generation failed")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	if err := s.addSession(clientBucket(r), id, establishedSession{channel: channel, lastUsed: time.Now()}); err != nil {
		s.refuseSession(w, err)
		return
	}

	writeJSON(w, http.StatusOK, types.HandshakeResponse{SessionID: id})
}

// refusePending maps a refused handshake onto the wire: a nonce collision is
// the client's to fix, a full store is one to retry.
func (s *Server) refusePending(w http.ResponseWriter, err error) {
	if errors.Is(err, errStoreFull) {
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeAttestationUnavailable, err.Error())
		return
	}
	writeErr(w, http.StatusConflict, types.ErrorCodeInvalidRequest, err.Error())
}

// refuseSession maps a refused session onto the wire. A colliding id is a
// 128-bit random collision, so it is this server's fault, not the caller's.
func (s *Server) refuseSession(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSessionInUse):
		s.log.Error("session id collision", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "session id generation failed")
	case errors.Is(err, errStoreFull):
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeAttestationUnavailable, err.Error())
	default:
		writeErr(w, http.StatusTooManyRequests, types.ErrorCodeTooManyRequests, err.Error())
	}
}

// handleTunnel terminates the over-encryption: it opens the sealed request
// envelope, forwards the reconstructed request to the backend (plaintext; the
// cluster raTLS mesh wraps that hop), and seals the response back to the client.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	channel := s.useSession(r.Header.Get(sessionHeader))
	if channel == nil {
		writeErr(w, http.StatusUnauthorized, types.ErrorCodeChannelError, "no over-encryption session")
		return
	}

	recBytes, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "read record")
		return
	}
	var rec overenc.Record
	if err := cbor.Unmarshal(recBytes, &rec); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "invalid record")
		return
	}
	plaintext, err := channel.Open(rec, overenc.RequestAAD())
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "decrypt failed")
		return
	}

	var env types.TunnelRequest
	if err := cbor.Unmarshal(plaintext, &env); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "invalid request envelope")
		return
	}

	resp, err := s.backend.Forward(r.Context(), env)
	if err != nil {
		s.log.Warn("backend forward failed", "method", env.Method, "path", env.Path, "error", err)
		resp = types.TunnelResponse{Status: http.StatusBadGateway, Body: []byte("backend error")}
	}

	respCBOR, err := cbor.Marshal(resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "marshal response envelope")
		return
	}
	out, err := channel.Seal(respCBOR, overenc.ResponseAAD())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "seal failed")
		return
	}
	writeCBOR(w, http.StatusOK, out)
}

// sweep evicts expired pending handshakes and idle established sessions.
func (s *Server) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.pending {
		if now.Sub(v.createdAt) > s.cfg.NonceTTL {
			s.dropPending(k)
		}
	}
	for k, v := range s.sessions {
		if now.Sub(v.lastUsed) > s.cfg.SessionTTL {
			s.dropSession(k)
		}
	}
}

// pendingRoom reports why a handshake for client may not be parked under
// nonce. handleAttestPQ asks before it mints anything, and addPending asks
// again under the lock that inserts.
func (s *Server) pendingRoom(client, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingRoomLocked(client, nonce)
}

func (s *Server) pendingRoomLocked(client, nonce string) error {
	if _, taken := s.pending[nonce]; taken {
		return errNonceInUse
	}
	// A client at its own bound makes room from its own entries, so the store
	// cannot grow and the global bound does not apply.
	if s.pendingBy.count(client) >= maxPendingPerClient {
		return nil
	}
	if len(s.pending) >= maxPendingSessions {
		if _, ok := s.pendingBy.admit(maxPendingSessions, client); !ok {
			return errStoreFull
		}
	}
	return nil
}

// addPending parks entry under nonce. A client past its own bound drops its
// oldest pending handshake; a full store drops from a client over its share
// (holders.admit).
func (s *Server) addPending(client, nonce string, entry pendingSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.pendingRoomLocked(client, nonce); err != nil {
		return err
	}
	switch {
	case s.pendingBy.count(client) >= maxPendingPerClient:
		s.dropPending(oldestPendingOf(s.pending, s.pendingBy.keys(client)))
	case len(s.pending) >= maxPendingSessions:
		over, ok := s.pendingBy.admit(maxPendingSessions, client)
		if !ok {
			return errStoreFull
		}
		s.dropPending(oldestPendingOf(s.pending, s.pendingBy.keys(over)))
	}
	entry.client = client
	s.pending[nonce] = entry
	s.pendingBy.add(client, nonce)
	return nil
}

// takePending removes and returns the handshake parked under nonce.
func (s *Server) takePending(nonce string) (pendingSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[nonce]
	if !ok {
		return pendingSession{}, false
	}
	s.dropPending(nonce)
	return entry, true
}

func (s *Server) dropPending(nonce string) {
	entry, ok := s.pending[nonce]
	if !ok {
		return
	}
	delete(s.pending, nonce)
	s.pendingBy.remove(entry.client, nonce)
}

// addSession stores an established channel under id. An established session is
// never evicted for a new one; a client at its own bound is refused.
func (s *Server) addSession(client, id string, entry establishedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.sessions[id]; taken {
		return errSessionInUse
	}
	if s.sessionsBy.count(client) >= maxSessionsPerClient {
		return errSessionsFull
	}
	if len(s.sessions) >= maxSessions {
		over, ok := s.sessionsBy.admit(maxSessions, client)
		if !ok {
			return errStoreFull
		}
		s.dropSession(idlestSessionOf(s.sessions, s.sessionsBy.keys(over)))
	}
	entry.client = client
	s.sessions[id] = entry
	s.sessionsBy.add(client, id)
	return nil
}

// useSession returns the channel id names, refreshing its idle deadline. An
// expired session is dropped and reported as absent.
func (s *Server) useSession(id string) *overenc.Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[id]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.Sub(entry.lastUsed) > s.cfg.SessionTTL {
		s.dropSession(id)
		return nil
	}
	entry.lastUsed = now
	s.sessions[id] = entry
	return entry.channel
}

func (s *Server) dropSession(id string) {
	entry, ok := s.sessions[id]
	if !ok {
		return
	}
	delete(s.sessions, id)
	s.sessionsBy.remove(entry.client, id)
}

func oldestPendingOf(pending map[string]pendingSession, held map[string]struct{}) string {
	var chosen string
	var at time.Time
	for nonce := range held {
		entry, ok := pending[nonce]
		if !ok {
			continue
		}
		if at.IsZero() || entry.createdAt.Before(at) {
			chosen, at = nonce, entry.createdAt
		}
	}
	return chosen
}

func idlestSessionOf(sessions map[string]establishedSession, held map[string]struct{}) string {
	var chosen string
	var at time.Time
	for id := range held {
		entry, ok := sessions[id]
		if !ok {
			continue
		}
		if at.IsZero() || entry.lastUsed.Before(at) {
			chosen, at = id, entry.lastUsed
		}
	}
	return chosen
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeCBOR(w http.ResponseWriter, status int, v any) {
	b, err := cbor.Marshal(v)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "marshal failed")
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	w.Write(b)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, types.ErrorResponse{Error: code, Message: msg})
}
