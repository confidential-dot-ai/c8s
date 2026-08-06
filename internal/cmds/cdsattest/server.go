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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-chi/chi/v5"

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
	// the attestation fetch and the handshake POST. Defaults to SessionTTL.
	NonceTTL time.Duration
}

type pendingSession struct {
	key        *overenc.ServerKey
	transcript []byte // identity transcript hash, the channel's HKDF salt
	createdAt  time.Time
}

type establishedSession struct {
	channel  *overenc.Channel
	lastUsed time.Time
}

// Server serves the c8s-verify endpoints.
type Server struct {
	cfg     Config
	log     *slog.Logger
	backend Backend

	mu       sync.Mutex
	pending  map[string]pendingSession     // nonce(b64url) -> server key
	sessions map[string]establishedSession // session id -> channel
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
		cfg.NonceTTL = cfg.SessionTTL
	}
	backend := cfg.Backend
	if backend == nil {
		backend = EchoBackend{}
	}
	return &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		backend:  backend,
		pending:  make(map[string]pendingSession),
		sessions: make(map[string]establishedSession),
	}
}

// Handler returns the chi router for the LB endpoints.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", s.handleReadyz)
	r.Get(wellKnownPrefix+"/attest-pq", s.handleAttestPQ)
	r.Get(wellKnownPrefix+"/attest-lb", s.handleAttestLB)
	// The pre-split endpoint. Kept registered so a stale client gets the
	// explicit versioned 400 — never a 404 it might treat as transient, and
	// never an alias or downgrade.
	r.Get(wellKnownPrefix+"/attestation", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest,
			"the /.well-known/c8s/attestation endpoint is gone: use attest-pq (encrypted session) or attest-lb (ordinary TLS)")
	})
	r.Post(wellKnownPrefix+"/handshake", s.handleHandshake)
	// Over-encrypted application traffic: a single tunnel endpoint. The real
	// method/path/headers/body are sealed inside the request envelope, so nginx
	// only needs to route this one fixed path to the sidecar.
	r.Post(wellKnownPrefix+"/tunnel", s.handleTunnel)
	return r
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

	s.sweep()
	s.mu.Lock()
	s.pending[nonceB64] = pendingSession{
		key:        key,
		transcript: append([]byte(nil), reportData...),
		createdAt:  time.Now(),
	}
	s.mu.Unlock()

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
	if s.cfg.ExpectedWorkload == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	notReady := func(reason string, detail ...any) {
		s.log.Warn("readiness gate withholding traffic", append([]any{"reason", reason}, detail...)...)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, reason)
	}
	// Exactly the load attest-pq/attest-lb do: reading and parsing the leaf
	// alone would report ready on a credential those endpoints refuse — an
	// expired leaf above all, which is what this gate exists to catch, since
	// stamped leaves carry a short TTL (issuer.MaxNamedLeafTTL).
	identity, err := loadMeshIdentity(s.cfg.MeshIdentityCertFile, s.cfg.MeshIdentityKeyFile, s.cfg.MeshIdentityCAFile)
	if err != nil {
		notReady("mesh identity credentials unusable", "error", err)
		return
	}
	workload, err := ratls.MatchedWorkloadFromCert(identity.leaf)
	switch {
	case err != nil:
		notReady("matched-workload stamp malformed", "error", err)
	case workload == nil:
		notReady("mesh identity leaf carries no matched-workload stamp")
	case workload.Name != s.cfg.ExpectedWorkload:
		// Both names are this front door's configuration and this body is
		// reachable from the public internet; name them only in the log.
		notReady("mesh identity leaf is stamped for a different workload",
			"stamped", workload.Name, "expected", s.cfg.ExpectedWorkload)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req types.HandshakeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "invalid JSON")
		return
	}

	s.sweep()
	now := time.Now()
	s.mu.Lock()
	entry, ok := s.pending[req.Nonce]
	if ok {
		delete(s.pending, req.Nonce)
	}
	s.mu.Unlock()
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
	s.mu.Lock()
	s.sessions[id] = establishedSession{channel: channel, lastUsed: time.Now()}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, types.HandshakeResponse{SessionID: id})
}

// handleTunnel terminates the over-encryption: it opens the sealed request
// envelope, forwards the reconstructed request to the backend (plaintext; the
// cluster raTLS mesh wraps that hop), and seals the response back to the client.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-C8s-Session")
	s.sweep()

	s.mu.Lock()
	now := time.Now()
	session, ok := s.sessions[id]
	switch {
	case ok && now.Sub(session.lastUsed) > s.cfg.SessionTTL:
		delete(s.sessions, id)
		session = establishedSession{} // expired => treat as no session
	case ok:
		session.lastUsed = now
		s.sessions[id] = session
	default: // case !ok
		session = establishedSession{}
	}
	s.mu.Unlock()

	if session.channel == nil {
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
	plaintext, err := session.channel.Open(rec, overenc.RequestAAD())
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
	out, err := session.channel.Seal(respCBOR, overenc.ResponseAAD())
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
	for k, v := range s.pending {
		if now.Sub(v.createdAt) > s.cfg.NonceTTL {
			delete(s.pending, k)
		}
	}
	for k, v := range s.sessions {
		if now.Sub(v.lastUsed) > s.cfg.SessionTTL {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
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
