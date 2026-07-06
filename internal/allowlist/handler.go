package allowlist

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// DefaultMaxWriteBodyBytes is the cap applied when Handler.MaxWriteBodyBytes
// is zero. Mutation payloads are tiny (digest + image), so a small cap is
// fine and protects against a malicious client forcing the handler to buffer
// megabytes just to compute a hash for auth.
const DefaultMaxWriteBodyBytes int64 = 64 * 1024

// Handler holds the dependencies for allowlist HTTP handlers.
type Handler struct {
	Store           *Store
	WriteAuthorizer WriteAuthorizer
	// MaxWriteBodyBytes caps mutation request bodies. Zero means
	// DefaultMaxWriteBodyBytes; negative values are clamped to the default
	// (callers shouldn't pass them but a runtime-bad value shouldn't open
	// the handler up to unbounded reads).
	MaxWriteBodyBytes int64
}

// WriteAuthorizer authorizes a mutation request given the raw request body
// (so the auth check can bind the token to the body's SHA-256, defeating
// captured-token replay against a different payload). Production wires
// operatorauth.Verifier.Authorize.
type WriteAuthorizer func(r *http.Request, body []byte) error

// HandleList handles GET /allowlist - returns all allowlisted digests.
// Emits a weak ETag derived from the store version; matching
// If-None-Match returns 304.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	version, digests, err := h.Store.ListAll()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	etag := `W/"` + version + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.AllowlistListResponse{
		Version: version,
		Digests: digests,
	})
}

// HandleAdd handles POST /allowlist - adds an image digest.
func (h Handler) HandleAdd(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	var req types.AllowlistAddRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// An absent digest field skips Digest's validating UnmarshalJSON, and a
	// zero digest would insert a row ListAll skips and Delete cannot name.
	if req.Digest.String() == "" {
		http.Error(w, "digest is required", http.StatusUnprocessableEntity)
		return
	}

	if err := h.Store.Add(req.Digest, req.Image); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("allowlist digest added", "digest", req.Digest.String(), "image", req.Image)
	w.WriteHeader(http.StatusNoContent)
}

// HandleDelete handles DELETE /allowlist - deletes image digests atomically.
func (h Handler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	var req types.AllowlistDeleteRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	allFound, err := h.Store.Delete(req.Digests)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !allFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	slog.Info("allowlist digests deleted", "count", len(req.Digests))
	w.WriteHeader(http.StatusNoContent)
}

// HandleReplace handles PUT /allowlist - atomically replaces the entire
// allowlist with the request's digest set. CDS assigns the new version.
func (h Handler) HandleReplace(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	var req types.AllowlistReplaceRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// A nil map ({} or "digests":null) is indistinguishable from a client bug
	// and would clear the allowlist, denying every image on every node. Clearing
	// must be spelled out as an explicit empty set: {"digests":{}}.
	if req.Digests == nil {
		http.Error(w, `digests is required (send {"digests":{}} to clear the allowlist)`, http.StatusUnprocessableEntity)
		return
	}

	if err := h.Store.Replace(req.Digests); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("allowlist replaced", "entries", len(req.Digests))
	w.WriteHeader(http.StatusNoContent)
}

// authorize reads the body (capped) and runs the configured authorizer.
// On success returns the body for downstream decoding.
func (h Handler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if h.WriteAuthorizer == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	cap := h.MaxWriteBodyBytes
	if cap <= 0 {
		cap = DefaultMaxWriteBodyBytes
	}
	body, ok := httputil.ReadCappedBody(w, r, cap)
	if !ok {
		return nil, false
	}
	if err := h.WriteAuthorizer(r, body); err != nil {
		slog.Warn("allowlist write rejected", "method", r.Method, "remote", r.RemoteAddr, "reason", err)
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}
