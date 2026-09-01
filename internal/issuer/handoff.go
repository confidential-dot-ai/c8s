package issuer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/teewebpki"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
	"github.com/confidential-dot-ai/c8s/pkg/issuerapi"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/cryptobyte"
)

// maxHandoffErrorBytes caps how much of an untrusted peer's non-2xx /handoff
// response body is read into HandoffStatusError. A few KB is plenty for an
// error message.
const (
	maxHandoffErrorBytes = 8 << 10
	// The encrypted state can contain 16 MiB of encoded application secrets,
	// a 1 MiB allowlist, 10,000 bounded ledger entries, tee-webpki state, EAR
	// overlap keys, and CA material. Forty-eight MiB leaves a small format
	// margin. The JSON response needs the ciphertext's base64 expansion.
	maxHandoffPlaintextBytes = 48 << 20
	maxHandoffResponseBytes  = 68 << 20
)

const (
	handoffProtocolLabel            = "c8s-cds-handoff-v1"
	handoffRequestSignaturePurpose  = "request-signature"
	handoffClusterSignaturePurpose  = "cluster-signature"
	handoffResponseSignaturePurpose = "response-signature"
	handoffPayloadKeyPurpose        = "payload-key"
	handoffPayloadAADPurpose        = "payload-aad"
)

// DefaultHandoffEARMaxAge is the maximum age of the requester's nonce-bound
// attest-key result. The normal token validity check still applies. This
// tighter bound stops an old, otherwise valid EAR from becoming a later
// successor request.
const DefaultHandoffEARMaxAge = 5 * time.Minute

// DefaultEndpointDrainDelay gives Kubernetes time to remove a predecessor
// from Service endpoints after its readiness becomes false. The predecessor
// stays frozen and continues read-only service during this delay.
// This is a graceful-drain bound. It is not proof of an atomic endpoint switch.
const DefaultEndpointDrainDelay = 5 * time.Second

// DefaultHandoffTransferLease limits how long a predecessor stays frozen when
// a selected successor receives state but never starts activation. The lease
// does not run after activation starts because the successor can then be
// mutable. Automatic thaw at that point could create two mutable CDS replicas.
const DefaultHandoffTransferLease = 5 * time.Minute

type HandoffRequest = issuerapi.HandoffRequest
type HandoffResponse = issuerapi.HandoffResponse
type HandoffActivateRequest = issuerapi.HandoffActivateRequest
type HandoffActivateResponse = issuerapi.HandoffActivateResponse
type HandoffConfirmRequest = issuerapi.HandoffConfirmRequest
type HandoffConfirmResponse = issuerapi.HandoffConfirmResponse
type HandoffAbortRequest = issuerapi.HandoffAbortRequest
type HandoffAbortResponse = issuerapi.HandoffAbortResponse

var (
	tokenValidationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cds_token_validation_failures_total",
		Help: "Token validation failures by reason.",
	}, []string{"reason"})

	measurementDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cds_measurement_denied_total",
		Help: "Requests denied due to measurement mismatch.",
	}, []string{"endpoint"})

	handoffEARExpirySeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_handoff_ear_expiry_seconds",
		Help: "Seconds until the handoff issuer EAR exp claim; negative when expired or unreadable.",
	})
)

// RecordTokenValidationFailure increments the per-reason counter when err is a
// *TokenValidationError. Untyped failures are logged so they aren't lost from
// the per-reason metric without any trace.
func RecordTokenValidationFailure(err error) {
	var tve *TokenValidationError
	if errors.As(err, &tve) {
		tokenValidationFailuresTotal.WithLabelValues(string(tve.Reason)).Inc()
		return
	}
	slog.Warn("token validation failed without typed reason", "error", err)
}

// RecordMeasurementDenied increments the per-endpoint measurement-denied
// counter (endpoint is the route label, e.g. "sign-csr", "handoff").
func RecordMeasurementDenied(endpoint string) {
	measurementDeniedTotal.WithLabelValues(endpoint).Inc()
}

// HandoffDeps carries the EAR verification context, active CA snapshot, and
// public bundle the handoff handler needs. It decouples the handler from any
// particular Issuer implementation.
type HandoffDeps struct {
	Logger              *slog.Logger
	KeyProvider         KeyProvider
	ExpectedIssuer      string
	AllowedMeasurements map[string]bool
	// OperatorKeysHash is the local CDS operator-key policy commitment. A
	// requester EAR must carry the exact same REPORTDATA-bound value.
	OperatorKeysHash string
	// ExpectedSuccessorWorkload is the matched-workload name that the current
	// CDS must have stamped on the successor's mesh certificate. This live
	// cluster identity is the property the removed measurement-only protocol
	// did not have.
	ExpectedSuccessorWorkload string
	// RequestEARMaxAge bounds how old the successor's nonce-bound attest-key
	// result may be. Zero uses DefaultHandoffEARMaxAge.
	RequestEARMaxAge time.Duration
	// EndpointDrainDelay is the minimum time a predecessor remains readable but
	// NotReady before it grants takeover. Zero uses DefaultEndpointDrainDelay.
	EndpointDrainDelay time.Duration
	// TransferLease is the maximum pre-activation freeze. Zero uses
	// DefaultHandoffTransferLease. The predecessor thaws only if activation has
	// not started.
	TransferLease time.Duration
	Bundle        *BundleManager // optional; nil falls back to caCert-only bundle PEM

	// Signer (bootstrapped via HandoffBootstrap) signs the response transcript.
	Signer *ecdsa.PrivateKey

	// EARSource yields the issuer EAR refreshed via /attest-key. Need not be
	// ready at construction: the bootstrap runs asynchronously and HandleHandoff
	// returns 503 until the first refresh populates it.
	EARSource HandoffEARSource

	// Snapshot returns the active CA material. ok=false means no bundle is
	// loaded (handler returns 503).
	Snapshot func() (snap CASnapshot, ok bool)
	// Resume releases store-level freezes after a transfer fails or its
	// pre-activation lease expires.
	Resume func()
	// AuthorizeWrite verifies the operator signature on an explicit handoff
	// abort. Nil disables abort.
	AuthorizeWrite func(*http.Request, []byte) error
}

// CASnapshot is the active CA material a handoff response transfers: the CA
// cert and its private key, plus the optional parent cert when the CA is an
// intermediate.
type CASnapshot struct {
	Cert       *x509.Certificate
	Key        *ecdsa.PrivateKey
	ParentCert *x509.Certificate // nil for a self-signed root CA
	// AllowlistVersion, Allowlist (floor) and Workloads are copied into the
	// encrypted payload so a rolling adoption preserves runtime operator state.
	AllowlistVersion string
	Allowlist        map[types.Digest]string
	Workloads        map[string]allowlist.Workload
	// TEEWebPKI carries the protected cluster TLS and ACME state when that
	// mode is enabled. It stays inside the recipient-bound ciphertext.
	TEEWebPKI *teewebpki.Snapshot
	// Secrets carries every application secret and its holder accounting. It
	// stays inside the recipient-bound ciphertext.
	Secrets *secrets.Snapshot
	// EARSigner carries the active EAR signer and live overlap keys.
	EARSigner *earsigner.Snapshot
	// SandboxLedger carries first-write-wins inventory bindings.
	SandboxLedger *sandboxledger.Snapshot
}

func (s CASnapshot) hasCAKeyPair() bool {
	return s.Cert != nil && s.Key != nil
}

// HandoffHandler wraps the active in-memory CA to attested replicas. The CA
// private key never leaves process memory except as recipient-bound ciphertext
// in the handoff response.
type HandoffHandler struct {
	deps      HandoffDeps
	earSource HandoffEARSource
	signer    *ecdsa.PrivateKey
	transfer  transferGate
	leader    leadershipGate
}

type leadershipPhase uint8

const (
	leadershipActive leadershipPhase = iota
	leadershipFrozen
	leadershipDraining
	leadershipTakeoverReady
	leadershipRetired
)

// leadershipGate holds a read lock for the full duration of each mutation.
// A snapshot takes the write lock. Thus no mutation can cross the snapshot.
type leadershipGate struct {
	mu        sync.RWMutex
	phase     leadershipPhase
	drainDone chan struct{}
}

// transferGate admits one active successor. A retry of the byte-identical
// request receives the same response. Any different request is refused. Each
// CDS process starts with a fresh gate, so the successor can authorize one
// later roll after it becomes the active CDS.
type transferGate struct {
	mu         sync.Mutex
	request    [sha256.Size]byte
	response   *HandoffResponse
	peerKey    [sha256.Size]byte
	snapshot   *CASnapshot
	generation uint64
	aborted    [sha256.Size]byte
}

// NewHandoffHandler validates the dependencies and returns a HandoffHandler.
//
// Does NOT require deps.EARSource.Current() to succeed at construction: the
// bootstrap runs asynchronously, and HandleHandoff returns 503 until the first
// refresh populates the source.
func NewHandoffHandler(deps HandoffDeps) (*HandoffHandler, error) {
	if deps.Signer == nil {
		return nil, fmt.Errorf("HandoffDeps.Signer is required")
	}
	if deps.EARSource == nil {
		return nil, fmt.Errorf("HandoffDeps.EARSource is required")
	}
	if deps.KeyProvider == nil {
		return nil, fmt.Errorf("HandoffDeps.KeyProvider is required")
	}
	if deps.Snapshot == nil {
		return nil, fmt.Errorf("HandoffDeps.Snapshot is required")
	}
	if len(deps.AllowedMeasurements) == 0 {
		return nil, fmt.Errorf("handoff requires a non-empty measurement allowlist")
	}
	if err := operatorauth.ValidateKeySetHash(deps.OperatorKeysHash); err != nil {
		return nil, fmt.Errorf("handoff requires an operator-key policy: %w", err)
	}
	if deps.ExpectedSuccessorWorkload == "" {
		deps.ExpectedSuccessorWorkload = "c8s-cds"
	}
	if !allowlist.ValidWorkloadName(deps.ExpectedSuccessorWorkload) {
		return nil, fmt.Errorf("handoff requires a valid expected successor workload name")
	}
	if deps.RequestEARMaxAge == 0 {
		deps.RequestEARMaxAge = DefaultHandoffEARMaxAge
	}
	if deps.RequestEARMaxAge <= 0 {
		return nil, fmt.Errorf("handoff request EAR max age must be positive")
	}
	if deps.EndpointDrainDelay == 0 {
		deps.EndpointDrainDelay = DefaultEndpointDrainDelay
	}
	if deps.EndpointDrainDelay < 0 {
		return nil, fmt.Errorf("handoff endpoint drain delay must be positive")
	}
	if deps.TransferLease == 0 {
		deps.TransferLease = DefaultHandoffTransferLease
	}
	if deps.TransferLease <= deps.EndpointDrainDelay {
		return nil, fmt.Errorf("handoff transfer lease must exceed endpoint drain delay")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &HandoffHandler{
		deps: deps, earSource: deps.EARSource, signer: deps.Signer,
		leader: leadershipGate{phase: leadershipActive},
	}, nil
}

// Active reports whether this CDS accepts mutations.
func (hh *HandoffHandler) Active() bool {
	hh.leader.mu.RLock()
	defer hh.leader.mu.RUnlock()
	return hh.leader.phase == leadershipActive
}

// Serving reports whether this CDS can continue read-only service.
// A frozen predecessor serves until the successor confirms activation.
func (hh *HandoffHandler) Serving() bool {
	hh.leader.mu.RLock()
	defer hh.leader.mu.RUnlock()
	return hh.leader.phase != leadershipRetired
}

// ReadyForTraffic reports whether Kubernetes may keep this CDS in Service
// endpoints. A draining predecessor stays readable but is not ready.
func (hh *HandoffHandler) ReadyForTraffic() bool {
	hh.leader.mu.RLock()
	defer hh.leader.mu.RUnlock()
	return hh.leader.phase != leadershipDraining && hh.leader.phase != leadershipTakeoverReady && hh.leader.phase != leadershipRetired
}

// StartFrozen configures an adopted successor before it starts serving.
func (hh *HandoffHandler) StartFrozen() {
	hh.leader.mu.Lock()
	hh.leader.phase = leadershipFrozen
	hh.leader.mu.Unlock()
}

// Promote makes a restored successor mutable after the predecessor retires.
func (hh *HandoffHandler) Promote() {
	hh.leader.mu.Lock()
	if hh.leader.phase == leadershipFrozen {
		hh.leader.phase = leadershipActive
	}
	hh.leader.mu.Unlock()
}

// GuardMutation rejects a write after handoff freeze. The read lock stays held
// until the handler finishes, so the transfer snapshot waits for in-flight
// mutations.
func (hh *HandoffHandler) GuardMutation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hh.leader.mu.RLock()
		defer hh.leader.mu.RUnlock()
		if hh.leader.phase != leadershipActive {
			http.Error(w, "CDS state is frozen for handoff", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IssuerEARSource exposes the source so callers can wire the expiry-metric
// updater without re-plumbing it.
func (hh *HandoffHandler) IssuerEARSource() HandoffEARSource { return hh.earSource }

type handoffPayload struct {
	CAKey             string                        `json:"ca_key"`
	CACertificate     string                        `json:"ca_certificate"`
	CABundle          string                        `json:"ca_bundle"`
	ParentCertificate string                        `json:"parent_certificate,omitempty"`
	AllowlistVersion  string                        `json:"allowlist_version"`
	Allowlist         map[types.Digest]string       `json:"allowlist"`
	Workloads         map[string]allowlist.Workload `json:"workloads,omitempty"`
	TEEWebPKI         *teewebpki.Snapshot           `json:"tee_webpki,omitempty"`
	Secrets           *secrets.Snapshot             `json:"secrets,omitempty"`
	EARSigner         *earsigner.Snapshot           `json:"ear_signer,omitempty"`
	SandboxLedger     *sandboxledger.Snapshot       `json:"sandbox_ledger,omitempty"`
}

// HandoffMaterial is the unwrapped result of a successful handoff.
type HandoffMaterial struct {
	CAKey            *ecdsa.PrivateKey
	CACert           *x509.Certificate
	ParentCert       *x509.Certificate
	Bundle           []*x509.Certificate
	AllowlistVersion string
	Allowlist        map[types.Digest]string
	Workloads        map[string]allowlist.Workload
	TEEWebPKI        *teewebpki.Snapshot
	Secrets          *secrets.Snapshot
	EARSigner        *earsigner.Snapshot
	SandboxLedger    *sandboxledger.Snapshot
	TransferID       string
	activate         func(context.Context) error
	confirm          func(context.Context) error
}

// Activate drains the predecessor and grants this successor permission to
// promote. The predecessor stays frozen and readable until Confirm succeeds.
func (m *HandoffMaterial) Activate(ctx context.Context) error {
	if m == nil || m.activate == nil {
		return fmt.Errorf("handoff activation is unavailable")
	}
	return m.activate(ctx)
}

// Confirm tells the frozen predecessor that this successor promoted the
// restored state. Only this call retires the predecessor.
func (m *HandoffMaterial) Confirm(ctx context.Context) error {
	if m == nil || m.confirm == nil {
		return fmt.Errorf("handoff confirmation is unavailable")
	}
	return m.confirm(ctx)
}

// HandoffClientDeps carries the EAR verification context the requester needs to
// validate the issuer's response.
type HandoffClientDeps struct {
	KeyProvider         KeyProvider
	ExpectedIssuer      string
	AllowedMeasurements map[string]bool
	// OperatorKeysHash is the local operator-key policy commitment expected
	// in the issuer's REPORTDATA-bound handoff EAR.
	OperatorKeysHash string
	// ClusterIdentity is the current CDS-issued mesh certificate and private
	// key. The HTTP client must present the same certificate on /handoff.
	ClusterIdentity *tls.Certificate
}

// HandoffStatusError is a non-2xx handoff response, typed so callers can
// distinguish disabled (404) from not-yet-bootstrapped (503).
type HandoffStatusError struct {
	Status int
	Body   string
}

func (e *HandoffStatusError) Error() string {
	return fmt.Sprintf("handoff peer returned %d: %s", e.Status, e.Body)
}

// HandleHandoff validates a replica EAR and returns the CA material encrypted
// to the requester's X25519 public key.
func (hh *HandoffHandler) HandleHandoff(w http.ResponseWriter, r *http.Request) {
	peerLeaf, err := hh.authorizeSuccessor(r)
	if err != nil {
		hh.deps.Logger.Warn("handoff denied: successor has no live-cluster identity", "error", err)
		http.Error(w, "forbidden: successor is not an admitted live-cluster workload", http.StatusForbidden)
		return
	}

	issuerEAR, err := hh.earSource.Current()
	if err != nil {
		hh.deps.Logger.Error("handoff EAR load failed", "error", err)
		http.Error(w, "handoff unavailable: issuer EAR load failed", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(issuerEAR) == "" {
		http.Error(w, "handoff unavailable: issuer EAR is not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request: failed to read body", http.StatusBadRequest)
		return
	}

	var req HandoffRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request: invalid JSON", http.StatusBadRequest)
		return
	}
	if req.EAR == "" || req.PublicKey == "" || req.Signature == "" || req.ClusterSignature == "" {
		http.Error(w, "bad request: ear, public_key, signature, and cluster_signature are required", http.StatusBadRequest)
		return
	}

	claims, err := ValidateEARToken(req.EAR, hh.deps.KeyProvider, hh.deps.ExpectedIssuer)
	if err != nil {
		RecordTokenValidationFailure(err)
		http.Error(w, "unauthorized: invalid requester attestation token", http.StatusUnauthorized)
		return
	}
	if err := checkRequiredMeasurement(claims, hh.deps.AllowedMeasurements, "handoff"); err != nil {
		RecordTokenValidationFailure(err)
		RecordMeasurementDenied("handoff")
		http.Error(w, "forbidden: requester measurement not allowed", http.StatusForbidden)
		return
	}
	if err := checkOperatorPolicy(claims, hh.deps.OperatorKeysHash, "requester"); err != nil {
		RecordTokenValidationFailure(err)
		http.Error(w, "forbidden: requester operator-key policy does not match", http.StatusForbidden)
		return
	}
	if err := checkHandoffEARAge(claims, hh.deps.RequestEARMaxAge, time.Now()); err != nil {
		RecordTokenValidationFailure(err)
		http.Error(w, "forbidden: requester attestation is too old", http.StatusForbidden)
		return
	}
	requestMessage, err := handoffRequestMessage(req.EAR, req.PublicKey)
	if err != nil {
		hh.deps.Logger.Warn("handoff requester transcript failed", "error", err)
		http.Error(w, "bad request: invalid requester handoff transcript", http.StatusBadRequest)
		return
	}
	if err := verifyHandoffSignature(claims, req.Signature, requestMessage, "requester"); err != nil {
		hh.deps.Logger.Warn("handoff requester key proof failed", "error", err)
		http.Error(w, "unauthorized: invalid requester key proof", http.StatusUnauthorized)
		return
	}
	clusterMessage, err := handoffClusterMessage(req.EAR, req.PublicKey)
	if err != nil {
		http.Error(w, "bad request: invalid cluster identity transcript", http.StatusBadRequest)
		return
	}
	if err := verifyClusterSignature(peerLeaf, req.ClusterSignature, clusterMessage); err != nil {
		hh.deps.Logger.Warn("handoff successor cluster-key proof failed", "error", err)
		http.Error(w, "unauthorized: invalid live-cluster key proof", http.StatusUnauthorized)
		return
	}

	requestID, err := handoffRequestID(req, peerLeaf)
	if err != nil {
		http.Error(w, "bad request: invalid handoff request", http.StatusBadRequest)
		return
	}
	hh.transfer.mu.Lock()
	defer hh.transfer.mu.Unlock()
	peerKeyHash := sha256.Sum256(peerLeaf.RawSubjectPublicKeyInfo)
	if hh.transfer.response != nil {
		if hh.transfer.request == requestID {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(*hh.transfer.response)
			return
		}
		// A container restart can create a new X25519 recipient key while it
		// keeps the selected CDS-issued mesh leaf. Re-encrypt the same frozen
		// snapshot to that new request. A different mesh leaf cannot replace the
		// selected successor automatically.
		if hh.transfer.peerKey != peerKeyHash || hh.transfer.snapshot == nil {
			http.Error(w, "conflict: a different successor already received this CDS state", http.StatusConflict)
			return
		}
		resp, err := hh.wrap(req, *hh.transfer.snapshot, issuerEAR)
		if err != nil {
			hh.deps.Logger.Error("handoff rewrap failed", "error", err)
			http.Error(w, "internal error: handoff rewrap failed", http.StatusInternalServerError)
			return
		}
		hh.transfer.request = requestID
		hh.transfer.response = &resp
		hh.armTransferLeaseLocked()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Stop new mutations and wait for any current mutation to finish. Keep
	// read-only service available while the successor restores.
	hh.leader.mu.Lock()
	if hh.leader.phase != leadershipActive {
		hh.leader.mu.Unlock()
		http.Error(w, "conflict: CDS is not active for a new handoff", http.StatusConflict)
		return
	}
	hh.leader.phase = leadershipFrozen
	snap, ok := hh.deps.Snapshot()
	hh.leader.mu.Unlock()
	if !ok || !snap.hasCAKeyPair() {
		hh.resumeAfterFailedTransfer()
		http.Error(w, "service unavailable: no certificates loaded", http.StatusServiceUnavailable)
		return
	}

	resp, err := hh.wrap(req, snap, issuerEAR)
	if err != nil {
		hh.resumeAfterFailedTransfer()
		hh.deps.Logger.Error("handoff wrap failed", "error", err)
		http.Error(w, "internal error: handoff wrap failed", http.StatusInternalServerError)
		return
	}
	hh.transfer.request = requestID
	hh.transfer.response = &resp
	hh.transfer.peerKey = peerKeyHash
	hh.transfer.snapshot = &snap
	hh.armTransferLeaseLocked()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		hh.deps.Logger.Error("handoff response encode failed", "error", err)
	}
}

// armTransferLeaseLocked starts or refreshes the pre-activation recovery
// lease. The caller holds transfer.mu. Once activation starts, expiry cannot
// thaw the predecessor because the successor can already have promoted.
func (hh *HandoffHandler) armTransferLeaseLocked() {
	hh.transfer.generation++
	generation := hh.transfer.generation
	time.AfterFunc(hh.deps.TransferLease, func() {
		resumed := false
		hh.transfer.mu.Lock()
		if hh.transfer.generation != generation {
			hh.transfer.mu.Unlock()
			return
		}
		hh.leader.mu.Lock()
		if hh.leader.phase != leadershipFrozen {
			hh.leader.mu.Unlock()
			hh.transfer.mu.Unlock()
			return
		}
		hh.leader.phase = leadershipActive
		hh.transfer.request = [sha256.Size]byte{}
		hh.transfer.response = nil
		hh.transfer.peerKey = [sha256.Size]byte{}
		hh.transfer.snapshot = nil
		resumed = true
		hh.leader.mu.Unlock()
		hh.transfer.mu.Unlock()
		if resumed && hh.deps.Resume != nil {
			hh.deps.Resume()
		}
	})
}

// resumeAfterFailedTransfer makes the predecessor mutable again when no
// encrypted transfer response exists. The caller holds transfer.mu, so no
// retry or activation can observe a half-committed transfer.
func (hh *HandoffHandler) resumeAfterFailedTransfer() {
	resumed := false
	hh.leader.mu.Lock()
	if hh.leader.phase == leadershipFrozen && hh.transfer.response == nil {
		hh.leader.phase = leadershipActive
		resumed = true
	}
	hh.leader.mu.Unlock()
	if resumed && hh.deps.Resume != nil {
		hh.deps.Resume()
	}
}

// HandleActivate gives takeover permission to the selected successor. The old
// CDS becomes NotReady, then stays frozen and readable. It does not retire
// until the restored successor is active and sends an authenticated Confirm.
func (hh *HandoffHandler) HandleActivate(w http.ResponseWriter, r *http.Request) {
	peerLeaf, err := hh.authorizeSuccessor(r)
	if err != nil {
		http.Error(w, "forbidden: successor is not an admitted live-cluster workload", http.StatusForbidden)
		return
	}
	var req HandoffActivateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.TransferID == "" || req.Signature == "" {
		http.Error(w, "bad request: transfer_id and signature are required", http.StatusBadRequest)
		return
	}
	requestID, err := decodeB64(req.TransferID, "transfer id")
	if err != nil || len(requestID) != sha256.Size {
		http.Error(w, "bad request: invalid transfer_id", http.StatusBadRequest)
		return
	}
	message, err := handoffTranscript("activate", req.TransferID)
	if err != nil || verifyClusterSignature(peerLeaf, req.Signature, message) != nil {
		http.Error(w, "unauthorized: invalid activation proof", http.StatusUnauthorized)
		return
	}

	hh.transfer.mu.Lock()
	defer hh.transfer.mu.Unlock()
	if hh.transfer.response == nil || !bytes.Equal(requestID, hh.transfer.request[:]) {
		http.Error(w, "conflict: transfer is not active", http.StatusConflict)
		return
	}
	if sha256.Sum256(peerLeaf.RawSubjectPublicKeyInfo) != hh.transfer.peerKey {
		http.Error(w, "conflict: activation identity differs from the successor", http.StatusConflict)
		return
	}
	// Idempotent activation is safe. The predecessor cannot resume. Retirement
	// uses a server-owned timer, so a client disconnect cannot wedge the CDS in
	// the NotReady draining phase. A retry waits on the same completion signal.
	hh.leader.mu.Lock()
	switch hh.leader.phase {
	case leadershipFrozen:
		hh.leader.phase = leadershipDraining
		hh.leader.drainDone = make(chan struct{})
		go hh.finishEndpointDrain(hh.leader.drainDone)
	case leadershipDraining, leadershipTakeoverReady, leadershipRetired:
		// Continue the existing drain or return the prior result.
	default:
		hh.leader.mu.Unlock()
		http.Error(w, "conflict: CDS is not frozen for activation", http.StatusConflict)
		return
	}
	drainDone := hh.leader.drainDone
	phase := hh.leader.phase
	hh.leader.mu.Unlock()

	if phase == leadershipDraining {
		select {
		case <-r.Context().Done():
			return
		case <-drainDone:
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HandoffActivateResponse{Activated: true})
}

// finishEndpointDrain completes once an authenticated successor starts
// activation. It must not use the request context. Otherwise a disconnected
// client can leave the predecessor NotReady and frozen forever.
func (hh *HandoffHandler) finishEndpointDrain(done chan struct{}) {
	timer := time.NewTimer(hh.deps.EndpointDrainDelay)
	defer timer.Stop()
	<-timer.C
	hh.leader.mu.Lock()
	if hh.leader.phase == leadershipDraining && hh.leader.drainDone == done {
		hh.leader.phase = leadershipTakeoverReady
		close(done)
	}
	hh.leader.mu.Unlock()
}

// HandleConfirm retires the predecessor only after the selected successor
// states that it promoted the restored state. A crash before this request
// leaves the predecessor frozen and readable. It does not destroy the only
// in-memory trust state.
func (hh *HandoffHandler) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	peerLeaf, err := hh.authorizeSuccessor(r)
	if err != nil {
		http.Error(w, "forbidden: successor is not an admitted live-cluster workload", http.StatusForbidden)
		return
	}
	var req HandoffConfirmRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.TransferID == "" || req.Signature == "" {
		http.Error(w, "bad request: transfer_id and signature are required", http.StatusBadRequest)
		return
	}
	requestID, err := decodeB64(req.TransferID, "transfer id")
	if err != nil || len(requestID) != sha256.Size {
		http.Error(w, "bad request: invalid transfer_id", http.StatusBadRequest)
		return
	}
	message, err := handoffTranscript("confirm", req.TransferID)
	if err != nil || verifyClusterSignature(peerLeaf, req.Signature, message) != nil {
		http.Error(w, "unauthorized: invalid confirmation proof", http.StatusUnauthorized)
		return
	}

	hh.transfer.mu.Lock()
	defer hh.transfer.mu.Unlock()
	if hh.transfer.response == nil || !bytes.Equal(requestID, hh.transfer.request[:]) {
		http.Error(w, "conflict: transfer is not active", http.StatusConflict)
		return
	}
	if sha256.Sum256(peerLeaf.RawSubjectPublicKeyInfo) != hh.transfer.peerKey {
		http.Error(w, "conflict: confirmation identity differs from the successor", http.StatusConflict)
		return
	}
	hh.leader.mu.Lock()
	switch hh.leader.phase {
	case leadershipTakeoverReady:
		hh.leader.phase = leadershipRetired
	case leadershipRetired:
		// A lost success response is safe to retry.
	default:
		hh.leader.mu.Unlock()
		http.Error(w, "service unavailable: predecessor drain is not complete", http.StatusServiceUnavailable)
		return
	}
	hh.leader.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HandoffConfirmResponse{Confirmed: true})
}

// HandleAbort resumes a frozen predecessor after an operator has removed and
// verified the selected successor is gone. It is an explicit recovery action:
// aborting while a promoted successor still runs creates split brain.
func (hh *HandoffHandler) HandleAbort(w http.ResponseWriter, r *http.Request) {
	if hh.deps.AuthorizeWrite == nil {
		http.Error(w, "operator recovery is disabled", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := hh.deps.AuthorizeWrite(r, body); err != nil {
		http.Error(w, "forbidden: invalid operator authorization", http.StatusForbidden)
		return
	}
	var req HandoffAbortRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.TransferID == "" {
		http.Error(w, "bad request: transfer_id is required", http.StatusBadRequest)
		return
	}
	requestID, err := decodeB64(req.TransferID, "transfer id")
	if err != nil || len(requestID) != sha256.Size {
		http.Error(w, "bad request: invalid transfer_id", http.StatusBadRequest)
		return
	}
	var id [sha256.Size]byte
	copy(id[:], requestID)

	hh.transfer.mu.Lock()
	if hh.transfer.response == nil && hh.transfer.aborted == id {
		hh.transfer.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HandoffAbortResponse{Aborted: true})
		return
	}
	if hh.transfer.response == nil || hh.transfer.request != id {
		hh.transfer.mu.Unlock()
		http.Error(w, "conflict: transfer is not active", http.StatusConflict)
		return
	}
	hh.leader.mu.Lock()
	switch hh.leader.phase {
	case leadershipFrozen, leadershipDraining, leadershipTakeoverReady:
		// An operator can recover these phases only after it removes and verifies
		// the selected successor is gone.
	case leadershipActive:
		hh.leader.mu.Unlock()
		hh.transfer.mu.Unlock()
		http.Error(w, "conflict: handoff cannot be aborted in this phase", http.StatusConflict)
		return
	case leadershipRetired:
		hh.leader.mu.Unlock()
		hh.transfer.mu.Unlock()
		http.Error(w, "conflict: confirmed handoff cannot be aborted", http.StatusConflict)
		return
	default:
		hh.leader.mu.Unlock()
		hh.transfer.mu.Unlock()
		http.Error(w, "conflict: unknown handoff phase", http.StatusConflict)
		return
	}
	wasDraining := hh.leader.phase == leadershipDraining
	hh.leader.phase = leadershipActive
	if wasDraining && hh.leader.drainDone != nil {
		close(hh.leader.drainDone)
	}
	hh.leader.drainDone = nil
	hh.transfer.generation++
	hh.transfer.request = [sha256.Size]byte{}
	hh.transfer.response = nil
	hh.transfer.peerKey = [sha256.Size]byte{}
	hh.transfer.snapshot = nil
	hh.transfer.aborted = id
	hh.leader.mu.Unlock()
	hh.transfer.mu.Unlock()
	if hh.deps.Resume != nil {
		hh.deps.Resume()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HandoffAbortResponse{Aborted: true})
}

func (hh *HandoffHandler) authorizeSuccessor(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("request has no TLS connection state")
	}
	matched, err := ratls.PeerMatchedWorkload(*r.TLS)
	if err != nil {
		return nil, err
	}
	if matched == nil || matched.EffectiveIdentity() != hh.deps.ExpectedSuccessorWorkload {
		got := ""
		if matched != nil {
			got = matched.EffectiveIdentity()
		}
		return nil, fmt.Errorf("matched workload %q does not equal %q", got, hh.deps.ExpectedSuccessorWorkload)
	}
	return r.TLS.PeerCertificates[0], nil
}

func checkHandoffEARAge(claims *EARClaims, maxAge time.Duration, now time.Time) error {
	if claims == nil || claims.IssuedAt == 0 {
		return &TokenValidationError{Reason: ReasonMalformed, Err: fmt.Errorf("requester EAR has no issued-at time")}
	}
	age := now.Sub(time.Unix(claims.IssuedAt, 0))
	if age < -JWTClockSkew {
		return &TokenValidationError{Reason: ReasonMalformed, Err: fmt.Errorf("requester EAR issued-at time is in the future")}
	}
	if age > maxAge+JWTClockSkew {
		return &TokenValidationError{Reason: ReasonExpired, Err: fmt.Errorf("requester EAR age %s exceeds %s", age, maxAge)}
	}
	return nil
}

func verifyClusterSignature(leaf *x509.Certificate, signature string, message []byte) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("successor mesh certificate public key is not ECDSA: %T", leaf.PublicKey)
	}
	sig, err := decodeB64(signature, "successor cluster signature")
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("successor cluster signature verification failed")
	}
	return nil
}

func handoffRequestID(req HandoffRequest, leaf *x509.Certificate) ([sha256.Size]byte, error) {
	transcript, err := handoffTranscript("request-id", req.EAR, req.PublicKey, req.Signature, req.ClusterSignature, encodeB64(leaf.Raw))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(transcript), nil
}

func (hh *HandoffHandler) wrap(req HandoffRequest, snap CASnapshot, issuerEAR string) (HandoffResponse, error) {
	if !snap.hasCAKeyPair() {
		return HandoffResponse{}, fmt.Errorf("handoff CA snapshot requires cert and key")
	}

	requesterPubRaw, err := decodeB64(req.PublicKey, "requester public key")
	if err != nil {
		return HandoffResponse{}, err
	}
	requesterPub, err := ecdh.X25519().NewPublicKey(requesterPubRaw)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("parse requester public key: %w", err)
	}

	keyPEM, err := certutil.MarshalECKeyPEM(snap.Key)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("marshal CA key: %w", err)
	}

	bundlePEM := certutil.EncodeCertPEM(snap.Cert.Raw)
	if hh.deps.Bundle != nil {
		bundlePEM = hh.deps.Bundle.BundlePEMForCurrent(snap.Cert)
	}

	payload := handoffPayload{
		CAKey:            string(keyPEM),
		CACertificate:    string(certutil.EncodeCertPEM(snap.Cert.Raw)),
		CABundle:         string(bundlePEM),
		AllowlistVersion: snap.AllowlistVersion,
		Allowlist:        snap.Allowlist,
		Workloads:        snap.Workloads,
		TEEWebPKI:        snap.TEEWebPKI,
		Secrets:          snap.Secrets,
		EARSigner:        snap.EARSigner,
		SandboxLedger:    snap.SandboxLedger,
	}
	if err := validateAllowlistSnapshot(payload.AllowlistVersion, payload.Allowlist); err != nil {
		return HandoffResponse{}, err
	}
	if payload.TEEWebPKI != nil {
		if err := teewebpki.ValidateSnapshot(*payload.TEEWebPKI); err != nil {
			return HandoffResponse{}, fmt.Errorf("validate tee-webpki handoff state: %w", err)
		}
	}
	if payload.Secrets != nil {
		if err := secrets.ValidateSnapshot(*payload.Secrets); err != nil {
			return HandoffResponse{}, fmt.Errorf("validate secret handoff state: %w", err)
		}
	}
	if payload.EARSigner != nil {
		if err := earsigner.ValidateSnapshot(*payload.EARSigner); err != nil {
			return HandoffResponse{}, fmt.Errorf("validate EAR signer handoff state: %w", err)
		}
	}
	if payload.SandboxLedger != nil {
		if err := sandboxledger.ValidateSnapshot(*payload.SandboxLedger, sandboxledger.MaxSnapshotEntries); err != nil {
			return HandoffResponse{}, fmt.Errorf("validate sandbox ledger handoff state: %w", err)
		}
	}
	if snap.ParentCert != nil {
		payload.ParentCertificate = string(certutil.EncodeCertPEM(snap.ParentCert.Raw))
	}

	plain, err := json.Marshal(payload)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("marshal handoff payload: %w", err)
	}
	if len(plain) > maxHandoffPlaintextBytes {
		return HandoffResponse{}, fmt.Errorf("handoff payload is %d bytes, limit is %d", len(plain), maxHandoffPlaintextBytes)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("generate handoff key: %w", err)
	}
	shared, err := priv.ECDH(requesterPub)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("derive handoff secret: %w", err)
	}

	serverPub := encodeB64(priv.PublicKey().Bytes())
	aead, err := handoffAEAD(shared, req.EAR, issuerEAR)
	if err != nil {
		return HandoffResponse{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return HandoffResponse{}, fmt.Errorf("generate handoff nonce: %w", err)
	}

	aad, err := handoffAAD(req.EAR, issuerEAR, req.PublicKey, serverPub)
	if err != nil {
		return HandoffResponse{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, aad)
	responseMessage, err := handoffResponseMessage(req.EAR, issuerEAR, req.PublicKey, serverPub)
	if err != nil {
		return HandoffResponse{}, err
	}
	signature, err := signHandoffMessage(hh.signer, responseMessage)
	if err != nil {
		return HandoffResponse{}, err
	}
	return HandoffResponse{
		IssuerEAR:  issuerEAR,
		PublicKey:  serverPub,
		Signature:  signature,
		Nonce:      encodeB64(nonce),
		Ciphertext: encodeB64(ciphertext),
	}, nil
}

// RunHandoffEARExpiryUpdater refreshes the handoff EAR expiry gauge on a fixed
// interval. On read or parse failure it sets the gauge negative so expiry
// alerts fail closed instead of preserving a stale positive value.
func RunHandoffEARExpiryUpdater(ctx context.Context, src HandoffEARSource, interval time.Duration, logger *slog.Logger) {
	update := func() {
		exp, err := src.ExpiresAt()
		if err != nil {
			logger.Warn("handoff EAR expiry unavailable for metrics", "error", err)
			handoffEARExpirySeconds.Set(-1)
			return
		}
		handoffEARExpirySeconds.Set(time.Until(exp).Seconds())
	}
	update()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		}
	}
}

// RequestHandoff drives the client side of the handoff protocol against
// peerURL and returns verified, decrypted CA material. requesterSigningKey is
// the ECDSA key bound into requesterEAR and signs the request transcript. A
// distinct, one-request X25519 key below encrypts the response; the CA private
// key appears only inside the decrypted HandoffMaterial.
type preparedHandoffRequest struct {
	deps         HandoffClientDeps
	peerURL      string
	requesterEAR string
	body         []byte
	request      HandoffRequest
	recipient    *ecdh.PrivateKey
	transferID   string
	client       *http.Client
	pinnedClient *http.Client
	peerAddress  string
	// activationRetryInterval is fixed in production. Tests shorten it.
	activationRetryInterval time.Duration
}

// RequestHandoff prepares and sends one handoff request. PullHandoff uses the
// two-step form so every retry has the same recipient key and request bytes.
func RequestHandoff(ctx context.Context, deps HandoffClientDeps, peerURL, requesterEAR string, requesterSigningKey *ecdsa.PrivateKey, client *http.Client) (*HandoffMaterial, error) {
	prepared, err := prepareHandoffRequest(deps, peerURL, requesterEAR, requesterSigningKey, client)
	if err != nil {
		return nil, err
	}
	return prepared.execute(ctx)
}

func prepareHandoffRequest(deps HandoffClientDeps, peerURL, requesterEAR string, requesterSigningKey *ecdsa.PrivateKey, client *http.Client) (*preparedHandoffRequest, error) {
	if strings.TrimSpace(requesterEAR) == "" {
		return nil, fmt.Errorf("handoff requester EAR is required")
	}
	if requesterSigningKey == nil {
		return nil, fmt.Errorf("handoff requester signing key is required")
	}
	if len(deps.AllowedMeasurements) == 0 {
		return nil, fmt.Errorf("handoff requires a non-empty measurement allowlist")
	}
	if err := operatorauth.ValidateKeySetHash(deps.OperatorKeysHash); err != nil {
		return nil, fmt.Errorf("handoff requires an operator-key policy: %w", err)
	}
	clusterLeaf, clusterKey, err := handoffClusterIdentity(deps.ClusterIdentity)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff recipient key: %w", err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	requestMessage, err := handoffRequestMessage(requesterEAR, pub)
	if err != nil {
		return nil, err
	}
	signature, err := signHandoffMessage(requesterSigningKey, requestMessage)
	if err != nil {
		return nil, err
	}
	clusterMessage, err := handoffClusterMessage(requesterEAR, pub)
	if err != nil {
		return nil, err
	}
	clusterSignature, err := signHandoffMessage(clusterKey, clusterMessage)
	if err != nil {
		return nil, fmt.Errorf("sign handoff with live-cluster identity %s: %w", clusterLeaf.Subject, err)
	}

	handoffReq := HandoffRequest{
		EAR:              requesterEAR,
		PublicKey:        pub,
		Signature:        signature,
		ClusterSignature: clusterSignature,
	}
	reqBody, err := json.Marshal(handoffReq)
	if err != nil {
		return nil, err
	}
	requestID, err := handoffRequestID(handoffReq, clusterLeaf)
	if err != nil {
		return nil, err
	}
	return &preparedHandoffRequest{
		deps: deps, peerURL: strings.TrimRight(peerURL, "/"), requesterEAR: requesterEAR,
		body: reqBody, request: handoffReq, recipient: priv,
		transferID: encodeB64(requestID[:]), client: client,
		activationRetryInterval: DefaultPullRetryInterval,
	}, nil
}

func (p *preparedHandoffRequest) execute(ctx context.Context) (*HandoffMaterial, error) {
	var peerAddress string
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if info.Conn != nil {
			peerAddress = info.Conn.RemoteAddr().String()
		}
	}}
	requestCtx := httptrace.WithClientTrace(ctx, trace)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, p.peerURL+"/handoff", bytes.NewReader(p.body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := p.client
	if p.pinnedClient != nil {
		client = p.pinnedClient
	}
	resp, err := client.Do(req)
	if peerAddress != "" && p.pinnedClient == nil {
		if pinErr := p.pinPredecessor(peerAddress); pinErr != nil {
			return nil, pinErr
		}
	}
	if err != nil {
		return nil, fmt.Errorf("request handoff: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Untrusted peer error body: cap it so a hostile or misconfigured
		// peer cannot balloon memory (or the retry log) with a huge response.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHandoffErrorBytes))
		return nil, &HandoffStatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	wire, err := io.ReadAll(io.LimitReader(resp.Body, maxHandoffResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read handoff response: %w", err)
	}
	if len(wire) > maxHandoffResponseBytes {
		return nil, fmt.Errorf("handoff response exceeds %d bytes", maxHandoffResponseBytes)
	}
	var hr HandoffResponse
	if err := json.Unmarshal(wire, &hr); err != nil {
		return nil, fmt.Errorf("decode handoff response: %w", err)
	}
	material, err := UnwrapHandoffResponse(hr, p.deps, p.requesterEAR, p.request.PublicKey, p.recipient)
	if err != nil {
		return nil, err
	}
	material.TransferID = p.transferID
	material.activate = func(ctx context.Context) error { return p.activate(ctx) }
	material.confirm = func(ctx context.Context) error { return p.confirm(ctx) }
	return material, nil
}

// pinPredecessor keeps all state-transfer control requests on the exact RA-TLS
// peer that returned the protected snapshot. The URL host stays unchanged, so
// TLS verification and SNI keep their original policy. Only TCP dialing is
// pinned. This path does not depend on the normal CDS Service endpoint after
// predecessor readiness becomes false.
func (p *preparedHandoffRequest) pinPredecessor(address string) error {
	base := p.client
	if base == nil {
		base = http.DefaultClient
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("handoff requires an HTTP transport that can pin the selected predecessor")
	}
	clone := httpTransport.Clone()
	baseDial := clone.DialContext
	if baseDial == nil {
		baseDial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	clone.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return baseDial(ctx, network, address)
	}
	clone.CloseIdleConnections()
	p.pinnedClient = &http.Client{
		Transport:     clone,
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
	p.peerAddress = address
	return nil
}

func (p *preparedHandoffRequest) activate(ctx context.Context) error {
	return p.sendTakeoverControl(ctx, "activate")
}

func (p *preparedHandoffRequest) confirm(ctx context.Context) error {
	return p.sendTakeoverControl(ctx, "confirm")
}

func (p *preparedHandoffRequest) sendTakeoverControl(ctx context.Context, action string) error {
	if p.pinnedClient == nil || p.peerAddress == "" {
		return fmt.Errorf("%s handoff: selected predecessor address is not pinned", action)
	}
	_, clusterKey, err := handoffClusterIdentity(p.deps.ClusterIdentity)
	if err != nil {
		return err
	}
	message, err := handoffTranscript(action, p.transferID)
	if err != nil {
		return err
	}
	signature, err := signHandoffMessage(clusterKey, message)
	if err != nil {
		return err
	}
	body, err := json.Marshal(HandoffActivateRequest{TransferID: p.transferID, Signature: signature})
	if err != nil {
		return err
	}
	interval := p.activationRetryInterval
	if interval <= 0 {
		interval = DefaultPullRetryInterval
	}
	for {
		retry, err := p.takeoverControlOnce(ctx, action, body)
		if err == nil || !retry {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%s handoff: %w", action, ctx.Err())
		case <-timer.C:
		}
	}
}

// takeoverControlOnce returns retry=true for errors where the predecessor can
// have completed the requested transition but the client did not receive it.
func (p *preparedHandoffRequest) takeoverControlOnce(ctx context.Context, action string, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.peerURL+"/handoff/"+action, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.pinnedClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, fmt.Errorf("%s handoff: %w", action, ctx.Err())
		}
		return true, fmt.Errorf("%s handoff: %w", action, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxHandoffErrorBytes))
		statusErr := &HandoffStatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(responseBody))}
		return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, statusErr
	}
	switch action {
	case "activate":
		var out HandoffActivateResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxHandoffErrorBytes)).Decode(&out); err != nil {
			return true, fmt.Errorf("decode handoff activation response: %w", err)
		}
		if !out.Activated {
			return false, fmt.Errorf("predecessor did not grant handoff activation")
		}
	case "confirm":
		var out HandoffConfirmResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxHandoffErrorBytes)).Decode(&out); err != nil {
			return true, fmt.Errorf("decode handoff confirmation response: %w", err)
		}
		if !out.Confirmed {
			return false, fmt.Errorf("predecessor did not confirm handoff takeover")
		}
	default:
		return false, fmt.Errorf("unsupported handoff control action %q", action)
	}
	return false, nil
}

func handoffClusterIdentity(identity *tls.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if identity == nil || len(identity.Certificate) == 0 || identity.PrivateKey == nil {
		return nil, nil, fmt.Errorf("handoff requires a CDS-issued cluster identity certificate and key")
	}
	leaf := identity.Leaf
	var err error
	if leaf == nil {
		leaf, err = x509.ParseCertificate(identity.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parse handoff cluster identity leaf: %w", err)
		}
	}
	key, ok := identity.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("handoff cluster identity private key is not ECDSA: %T", identity.PrivateKey)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("handoff cluster identity certificate does not match its private key")
	}
	return leaf, key, nil
}

// UnwrapHandoffResponse verifies the issuer EAR + signature, decrypts the
// recipient-bound payload, and returns the parsed CA material.
func UnwrapHandoffResponse(resp HandoffResponse, deps HandoffClientDeps, requesterEAR, requesterPub string, requesterKey *ecdh.PrivateKey) (*HandoffMaterial, error) {
	if resp.IssuerEAR == "" || resp.PublicKey == "" || resp.Signature == "" || resp.Nonce == "" || resp.Ciphertext == "" {
		return nil, fmt.Errorf("handoff response missing issuer_ear, public_key, signature, nonce, or ciphertext")
	}

	claims, err := ValidateEARToken(resp.IssuerEAR, deps.KeyProvider, deps.ExpectedIssuer)
	if err != nil {
		RecordTokenValidationFailure(err)
		return nil, fmt.Errorf("validate handoff issuer EAR: %w", err)
	}
	if err := checkRequiredMeasurement(claims, deps.AllowedMeasurements, "handoff"); err != nil {
		RecordTokenValidationFailure(err)
		RecordMeasurementDenied("handoff")
		return nil, fmt.Errorf("validate handoff issuer measurement: %w", err)
	}
	if err := checkOperatorPolicy(claims, deps.OperatorKeysHash, "issuer"); err != nil {
		RecordTokenValidationFailure(err)
		return nil, fmt.Errorf("validate handoff issuer operator-key policy: %w", err)
	}
	responseMessage, err := handoffResponseMessage(requesterEAR, resp.IssuerEAR, requesterPub, resp.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := verifyHandoffSignature(claims, resp.Signature, responseMessage, "issuer"); err != nil {
		return nil, err
	}

	peerPubRaw, err := decodeB64(resp.PublicKey, "handoff peer public key")
	if err != nil {
		return nil, err
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse handoff peer public key: %w", err)
	}
	shared, err := requesterKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("derive handoff secret: %w", err)
	}
	aead, err := handoffAEAD(shared, requesterEAR, resp.IssuerEAR)
	if err != nil {
		return nil, err
	}

	nonce, err := decodeB64(resp.Nonce, "handoff nonce")
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("handoff nonce length = %d, want %d", len(nonce), aead.NonceSize())
	}
	ciphertext, err := decodeB64(resp.Ciphertext, "handoff ciphertext")
	if err != nil {
		return nil, err
	}
	aad, err := handoffAAD(requesterEAR, resp.IssuerEAR, requesterPub, resp.PublicKey)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt handoff payload: %w", err)
	}
	return ParseHandoffPayload(plain)
}

// ParseHandoffPayload decodes a decrypted handoff payload into typed material
// and validates the CA cert/key pair.
func ParseHandoffPayload(plain []byte) (*HandoffMaterial, error) {
	if len(plain) > maxHandoffPlaintextBytes {
		return nil, fmt.Errorf("handoff payload exceeds %d bytes", maxHandoffPlaintextBytes)
	}
	var payload handoffPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("parse handoff payload: %w", err)
	}
	if payload.CAKey == "" || payload.CACertificate == "" || payload.CABundle == "" {
		return nil, fmt.Errorf("handoff payload missing CA fields")
	}
	if err := validateAllowlistSnapshot(payload.AllowlistVersion, payload.Allowlist); err != nil {
		return nil, err
	}
	if payload.TEEWebPKI != nil {
		if err := teewebpki.ValidateSnapshot(*payload.TEEWebPKI); err != nil {
			return nil, fmt.Errorf("validate tee-webpki handoff state: %w", err)
		}
	}
	if payload.Secrets != nil {
		if err := secrets.ValidateSnapshot(*payload.Secrets); err != nil {
			return nil, fmt.Errorf("validate secret handoff state: %w", err)
		}
	}
	if payload.EARSigner != nil {
		if err := earsigner.ValidateSnapshot(*payload.EARSigner); err != nil {
			return nil, fmt.Errorf("validate EAR signer handoff state: %w", err)
		}
	}
	if payload.SandboxLedger != nil {
		if err := sandboxledger.ValidateSnapshot(*payload.SandboxLedger, sandboxledger.MaxSnapshotEntries); err != nil {
			return nil, fmt.Errorf("validate sandbox ledger handoff state: %w", err)
		}
	}

	caKey, err := certutil.ParseECPrivateKey([]byte(payload.CAKey))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA key: %w", err)
	}
	caCert, err := certutil.ParseCertificatePEM([]byte(payload.CACertificate))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA certificate: %w", err)
	}
	if err := ValidateCAKeyPair(caCert, caKey); err != nil {
		return nil, err
	}

	certs, err := certutil.ParsePEMCertificates([]byte(payload.CABundle))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA bundle: %w", err)
	}
	var parentCert *x509.Certificate
	if payload.ParentCertificate != "" {
		parentCert, err = certutil.ParseCertificatePEM([]byte(payload.ParentCertificate))
		if err != nil {
			return nil, fmt.Errorf("parse handoff parent certificate: %w", err)
		}
	}

	return &HandoffMaterial{
		CAKey:            caKey,
		CACert:           caCert,
		ParentCert:       parentCert,
		Bundle:           certs,
		AllowlistVersion: payload.AllowlistVersion,
		Allowlist:        payload.Allowlist,
		Workloads:        payload.Workloads,
		TEEWebPKI:        payload.TEEWebPKI,
		Secrets:          payload.Secrets,
		EARSigner:        payload.EARSigner,
		SandboxLedger:    payload.SandboxLedger,
	}, nil
}

func validateAllowlistSnapshot(version string, digests map[types.Digest]string) error {
	parsedVersion, err := strconv.ParseUint(version, 10, 64)
	if err != nil || parsedVersion == 0 {
		return fmt.Errorf("invalid handoff allowlist version %q", version)
	}
	if digests == nil {
		return fmt.Errorf("handoff allowlist digests are required")
	}
	return nil
}

// ValidateCAKeyPair confirms a parsed CA certificate is currently usable for
// signing and that key matches the cert's public key.
func ValidateCAKeyPair(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if cert == nil {
		return fmt.Errorf("handoff CA certificate is required")
	}
	if key == nil {
		return fmt.Errorf("handoff CA key is required")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return fmt.Errorf("handoff CA certificate is not a CA")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("handoff CA certificate cannot sign certificates")
	}
	now := time.Now()
	if cert.NotBefore.After(now) || !cert.NotAfter.After(now) {
		return fmt.Errorf("handoff CA certificate is not currently valid")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("handoff CA certificate has non-ECDSA public key: %T", cert.PublicKey)
	}
	if !key.PublicKey.Equal(pub) {
		return fmt.Errorf("handoff CA key does not match certificate")
	}
	return nil
}

func checkRequiredMeasurement(claims *EARClaims, allowed map[string]bool, endpoint string) error {
	if len(allowed) == 0 {
		return &TokenValidationError{
			Reason: ReasonMeasurementDenied,
			Err:    fmt.Errorf("measurement allowlist required for %s", endpoint),
		}
	}
	return CheckMeasurement(claims, allowed, endpoint)
}

func checkOperatorPolicy(claims *EARClaims, expected, label string) error {
	if claims == nil || claims.OperatorKeysHash == "" {
		return &TokenValidationError{
			Reason: ReasonOperatorPolicy,
			Err:    fmt.Errorf("%s EAR is missing %s claim", label, earclaims.OperatorKeysHash),
		}
	}
	if err := operatorauth.ValidateKeySetHash(claims.OperatorKeysHash); err != nil {
		return &TokenValidationError{
			Reason: ReasonOperatorPolicy,
			Err:    fmt.Errorf("%s EAR has invalid %s claim: %w", label, earclaims.OperatorKeysHash, err),
		}
	}
	if claims.OperatorKeysHash != expected {
		return &TokenValidationError{
			Reason: ReasonOperatorPolicy,
			Err:    fmt.Errorf("%s EAR operator-key policy %s does not match expected %s", label, claims.OperatorKeysHash, expected),
		}
	}
	return nil
}

func signHandoffMessage(key *ecdsa.PrivateKey, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign handoff key proof: %w", err)
	}
	return encodeB64(sig), nil
}

func verifyHandoffSignature(claims *EARClaims, signature string, message []byte, label string) error {
	if claims.TEEPubKey == "" {
		return fmt.Errorf("%s EAR is missing %s claim", label, earclaims.TEEPublicKey)
	}
	pubDER, err := decodeB64(claims.TEEPubKey, label+" "+earclaims.TEEPublicKey)
	if err != nil {
		return err
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("parse %s %s: %w", label, earclaims.TEEPublicKey, err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s %s is not ECDSA: %T", label, earclaims.TEEPublicKey, pubAny)
	}
	sig, err := decodeB64(signature, label+" handoff signature")
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("%s handoff signature verification failed", label)
	}
	return nil
}

func handoffRequestMessage(ear, requesterPub string) ([]byte, error) {
	return handoffTranscript(handoffRequestSignaturePurpose, ear, requesterPub)
}

func handoffClusterMessage(ear, requesterPub string) ([]byte, error) {
	return handoffTranscript(handoffClusterSignaturePurpose, ear, requesterPub)
}

func handoffResponseMessage(requesterEAR, issuerEAR, requesterPub, issuerPub string) ([]byte, error) {
	return handoffTranscript(handoffResponseSignaturePurpose, requesterEAR, issuerEAR, requesterPub, issuerPub)
}

func handoffAEAD(shared []byte, requesterEAR, issuerEAR string) (cipher.AEAD, error) {
	info, err := handoffTranscript(handoffPayloadKeyPurpose, requesterEAR, issuerEAR)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("derive handoff key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create handoff cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create handoff aead: %w", err)
	}
	return aead, nil
}

func handoffAAD(requesterEAR, issuerEAR, requesterPub, issuerPub string) ([]byte, error) {
	return handoffTranscript(handoffPayloadAADPurpose, requesterEAR, issuerEAR, requesterPub, issuerPub)
}

// handoffTranscript TLS-style length-prefixes every signed, KDF, and
// AEAD-authenticated transcript component. The first two components are the
// protocol label and purpose-specific domain separator.
func handoffTranscript(purpose string, fields ...string) ([]byte, error) {
	components := make([]string, 0, 2+len(fields))
	components = append(components, handoffProtocolLabel, purpose)
	components = append(components, fields...)

	var builder cryptobyte.Builder
	for _, component := range components {
		component := []byte(component)
		builder.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(component)
		})
	}
	out, err := builder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build handoff transcript: %w", err)
	}
	return out, nil
}

func encodeB64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeB64(s, label string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return data, nil
}
