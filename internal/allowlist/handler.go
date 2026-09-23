package allowlist

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// DefaultMaxWriteBodyBytes caps a mutation body when Handler.MaxWriteBodyBytes
// is zero. One entry fits; the deployed handler raises this so a full document
// fits (see the cds router's allowlist write cap).
const DefaultMaxWriteBodyBytes int64 = 64 * 1024

// errAbsent is a delete of a workload the store does not hold. It travels out
// of the mutation closure so Apply skips the publication: nothing changed.
var errAbsent = errors.New("workload not found")

// Handler holds the dependencies for allowlist HTTP handlers.
type Handler struct {
	Store           *Store
	WriteAuthorizer WriteAuthorizer
	// MaxWriteBodyBytes caps mutation request bodies. Zero means
	// DefaultMaxWriteBodyBytes; a non-positive value clamps to the default.
	MaxWriteBodyBytes int64
	// Publications is the coordinator behind this endpoint: it serves the
	// active document and publishes every mutation. It is required.
	Publications *Publications
}

// WriteAuthorizer authorizes a mutation given the raw request body, so the
// check binds the token to the body's SHA-256 (defeating captured-token replay
// against a different payload). Production wires operatorauth.Verifier.Authorize.
type WriteAuthorizer func(r *http.Request, body []byte) error

// HandleList handles GET /allowlist: the ACTIVE allowlist document as canonical
// JSON. Emits a weak ETag from its version; a matching If-None-Match returns
// 304.
//
// A published version the coordinator has not switched to is deliberately
// invisible here. An enforcer that follows only this endpoint must never admit
// a rule before the barrier accounting has run.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	body, version, err := h.Publications.Active.ActiveBytes()
	if err != nil {
		slog.Error("allowlist read failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	etag := `W/"` + strconv.FormatUint(version, 10) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
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

	if !h.apply(w, r, func() error { return h.Store.ReplaceAll(al) }) {
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
	if !h.apply(w, r, func() error { return h.Store.PutWorkload(name, *entry) }) {
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
	ok := h.apply(w, r, func() error {
		found, err := h.Store.DeleteWorkload(name)
		if err != nil {
			return err
		}
		if !found {
			return errAbsent
		}
		return nil
	})
	if !ok {
		return
	}

	slog.Info("allowlist workload deleted", "name", name)
	w.WriteHeader(http.StatusNoContent)
}

// apply runs one mutation through the publication lock and answers the failure
// itself, so each handler is left with the success path.
//
// The refusal that matters is 409: a rollout is outstanding, so the store was
// not touched and the operator repeats the whole request later.
func (h Handler) apply(w http.ResponseWriter, r *http.Request, mutate func() error) bool {
	err := h.Publications.Apply(h.Store, mutate)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrBlocked):
		slog.Info("allowlist write refused while a policy update is outstanding", "method", r.Method, "path", r.URL.Path)
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, errAbsent):
		w.WriteHeader(http.StatusNotFound)
	case errors.Is(err, ErrInvalidWorkload):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, ErrNotPublished):
		slog.Error("allowlist mutation committed but not published", "error", err)
		http.Error(w, ErrNotPublished.Error(), http.StatusInternalServerError)
	default:
		slog.Error("allowlist mutation failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
	return false
}

// authorize reads the body (capped) and runs the configured authorizer.
// On success returns the body for downstream decoding.
func (h Handler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if h.WriteAuthorizer == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	max := h.MaxWriteBodyBytes
	if max <= 0 {
		max = DefaultMaxWriteBodyBytes
	}
	body, ok := httputil.ReadCappedBody(w, r, max)
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
