package allowlist

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// DefaultMaxWriteBodyBytes caps a mutation body when Handler.MaxWriteBodyBytes
// is zero. One entry fits; the deployed handler raises this so a full document
// fits (see the cds router's allowlist write cap).
const DefaultMaxWriteBodyBytes int64 = 64 * 1024

// Handler holds the dependencies for allowlist HTTP handlers.
type Handler struct {
	Store           *Store
	WriteAuthorizer WriteAuthorizer
	// MaxWriteBodyBytes caps mutation request bodies. Zero means
	// DefaultMaxWriteBodyBytes; a non-positive value clamps to the default.
	MaxWriteBodyBytes int64
}

// WriteAuthorizer authorizes a mutation given the raw request body, so the
// check binds the token to the body's SHA-256 (defeating captured-token replay
// against a different payload). Production wires operatorauth.Verifier.Authorize.
type WriteAuthorizer func(r *http.Request, body []byte) error

// HandleList handles GET /allowlist: the full allowlist document as canonical
// JSON. Emits a weak ETag from the store version; a matching If-None-Match
// returns 304.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	doc, version, err := h.Store.LoadAll()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	etag := `W/"` + version + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	body, err := doc.Canonical()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// HandleReplaceAll handles PUT /allowlist: validate the full document and swap
// it in atomically. CDS assigns the new version.
func (h Handler) HandleReplaceAll(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	al, err := pkgallowlist.ParseJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if err := h.Store.ReplaceAll(al); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("allowlist replaced", "workloads", len(al.Workloads))
	w.WriteHeader(http.StatusNoContent)
}

// HandlePutWorkload handles PUT /allowlist/workloads/{name}: validate the entry
// body and upsert it under the path name. An out-of-spec name or body is 422.
func (h Handler) HandlePutWorkload(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	entry, err := pkgallowlist.ParseWorkloadJSON(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	name := chi.URLParam(r, "name")
	if err := h.Store.PutWorkload(name, *entry); err != nil {
		if errors.Is(err, ErrInvalidWorkload) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("allowlist workload put", "name", name)
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteWorkload handles DELETE /allowlist/workloads/{name}: remove the
// named entry, 404 if absent.
func (h Handler) HandleDeleteWorkload(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r); !ok {
		return
	}

	name := chi.URLParam(r, "name")
	found, err := h.Store.DeleteWorkload(name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	slog.Info("allowlist workload deleted", "name", name)
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
