package cds

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/coordinator"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// publicationHandler serves the six publication and state endpoints under
// /.well-known/c8s from one coordinator.
//
// Reads are unauthenticated: RA-TLS already authenticates CDS and every answer
// is self-verifying. Participant writes carry the sender's boot-key signature,
// which the coordinator checks against the key that boot enrolled with. There
// is no operator endpoint here at all — the rollout is automatic, and the only
// operator input is the allowlist mutation that publishes.
type publicationHandler struct {
	Coordinator *coordinator.Coordinator
	// MaxWriteBodyBytes caps a challenge or participant request body.
	MaxWriteBodyBytes int64
}

// handleLatest serves the publication head. It says what was published, not
// what is active: a verifier reads the state statement for that.
func (h publicationHandler) handleLatest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, h.Coordinator.Head())
}

// handleObject serves the exact stored bytes of a content-addressed object, so
// a client can rehash what it was given.
func (h publicationHandler) handleObject(w http.ResponseWriter, r *http.Request) {
	body, err := h.Coordinator.Object("sha256:" + chi.URLParam(r, "hex"))
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (h publicationHandler) handleState(w http.ResponseWriter, _ *http.Request) {
	state, err := h.Coordinator.State()
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, state)
}

// handleChallenge signs the current statement against the caller's nonce. It is
// a POST because it has a body, but it is a read: it needs no authorization.
func (h publicationHandler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req policystate.ChallengeRequest
	if !decodeBody(w, r, h.MaxWriteBodyBytes, &req) {
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		http.Error(w, "nonce is not unpadded base64url", http.StatusUnprocessableEntity)
		return
	}
	if len(nonce) < policystate.MinNonceLen || len(nonce) > policystate.MaxNonceLen {
		http.Error(w, fmt.Sprintf("nonce is %d bytes, want %d..%d", len(nonce), policystate.MinNonceLen, policystate.MaxNonceLen), http.StatusUnprocessableEntity)
		return
	}
	challenged, err := h.Coordinator.Challenge(nonce)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, challenged)
}

func (h publicationHandler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var env policystate.Envelope[policystate.Enrollment]
	if !decodeBody(w, r, h.MaxWriteBodyBytes, &env) {
		return
	}
	if err := h.Coordinator.Enroll(env); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h publicationHandler) handleAck(w http.ResponseWriter, r *http.Request) {
	var env policystate.Envelope[policystate.Ack]
	if !decodeBody(w, r, h.MaxWriteBodyBytes, &env) {
		return
	}
	if err := h.Coordinator.Ack(env); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h publicationHandler) handleComplete(w http.ResponseWriter, r *http.Request) {
	var env policystate.Envelope[policystate.Completion]
	if !decodeBody(w, r, h.MaxWriteBodyBytes, &env) {
		return
	}
	if err := h.Coordinator.Complete(env); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodeBody reads the capped body and parses it strictly. Strictness is the
// point: a field the sender meant and the parser dropped would be a field the
// signature covered and the coordinator did not.
func decodeBody(w http.ResponseWriter, r *http.Request, maxBytes int64, out any) bool {
	body, ok := httputil.ReadCappedBody(w, r, maxBytes)
	if !ok {
		return false
	}
	if err := policystate.Decode(body, out); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	return true
}

// fail maps a coordinator rejection onto a status. Anything unclassified is a
// server fault: it is logged in full and answered with nothing.
func (h publicationHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coordinator.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, coordinator.ErrConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, coordinator.ErrInvalid):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, coordinator.ErrUnauthenticated):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		slog.Error("coordinator request failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		slog.Error("encode publication response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// policyPublisher records an allowlist mutation as the next published version
// and opens the update that rolls it out.
type policyPublisher struct {
	coordinator *coordinator.Coordinator
}

func (p policyPublisher) CanPublish() error { return p.coordinator.CanPublish() }

func (p policyPublisher) Publish(canonical []byte, authorizedBy string) error {
	_, err := p.coordinator.Publish(canonical, authorizedBy)
	return err
}

// activePolicy is the one adapter every consumer of the effective policy reads
// through: certificate issuance (PolicySnapshot) and secret release
// (secrets.CachedPolicy). Both must see the ACTIVE document — the one the
// coordinator has switched to — never the newest published version.
type activePolicy struct {
	coordinator *coordinator.Coordinator
}

// LoadAll returns the active document and the version that names it.
func (a activePolicy) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	doc, _, version, _, err := a.coordinator.Active()
	if err != nil {
		return nil, "", err
	}
	return doc, strconv.FormatUint(version, 10), nil
}

// Version names the active document without loading it, so a cache decides
// whether to reload from one cheap read.
func (a activePolicy) Version() (string, error) {
	version, err := a.coordinator.ActiveVersion()
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(version, 10), nil
}

// ActiveBytes returns the exact published bytes of the active document and its
// version, so GET /allowlist serves what was published rather than a
// re-encoding of a parse.
func (a activePolicy) ActiveBytes() ([]byte, uint64, error) {
	_, raw, version, _, err := a.coordinator.Active()
	return raw, version, err
}

// Generation moves on every committed coordinator change, so a memoized
// snapshot is rebuilt after a switch — which changes the active policy without
// appending to the journal — and not only after a store write.
func (a activePolicy) Generation() uint64 {
	return a.coordinator.Generation()
}

// openCoordinator opens the coordinator database beside the allowlist store. An
// empty path keeps it in memory, which is what a test or a deployment without
// durable storage gets.
func openCoordinator(path string, cfg config) (*coordinator.Coordinator, error) {
	opts := coordinator.Options{DeploymentID: cfg.deploymentID}
	if path == "" {
		return coordinator.OpenInMemory(opts)
	}
	return coordinator.Open(path, opts)
}

// coordinatorPath returns where the coordinator database lives: beside the
// allowlist database, or nowhere (in memory) when there is none.
func coordinatorPath(cfg config) string {
	if cfg.allowlistDB == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cfg.allowlistDB), "coordinator.db")
}

// bootstrapPolicy publishes the store's document so the journal and the store
// describe the same policy before anything serves.
//
// On a first start that is version 1, which switches and completes at once
// because nothing has enrolled yet. On a restart whose seed added entries it is
// the next version, rolled out like any other. A store that already holds
// entries the journal never published is refused: importing them would publish
// a policy under this deployment's authority that no operator authorized in
// this history.
func bootstrapPolicy(store *allowlist.Store, coord *coordinator.Coordinator, seedAdded int) error {
	head := coord.Head()
	if head.Version > 0 && seedAdded == 0 {
		return nil
	}
	doc, _, err := store.LoadAll()
	if err != nil {
		return fmt.Errorf("read allowlist for publication: %w", err)
	}
	if head.Version == 0 && len(doc.Workloads) > seedAdded {
		return fmt.Errorf("the allowlist store holds %d entries but the coordinator journal is empty: there is no published history for them. Start from an empty allowlist store, or seed one with --allowlist-seed",
			len(doc.Workloads))
	}
	canonical, err := doc.Canonical()
	if err != nil {
		return fmt.Errorf("canonicalize allowlist for publication: %w", err)
	}
	result, err := coord.Publish(canonical, policystate.AuthorizedBySeed)
	if err != nil {
		return fmt.Errorf("publish the installed allowlist: %w", err)
	}
	slog.Info("published the installed allowlist",
		"version", result.Version, "policy_digest", result.PolicyDigest, "seed_entries_added", seedAdded)
	return nil
}

// publicationAuthority names the authority a publication is recorded under. The
// operator verifier reports only that some pinned key signed, not which, so the
// record names the pinned key set rather than one key.
func publicationAuthority(operatorKeysHash string) string {
	if operatorKeysHash == "" {
		return policystate.AuthorizedBySeed
	}
	return "operator-keys:" + operatorKeysHash
}
