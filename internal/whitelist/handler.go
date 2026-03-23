package whitelist

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/pkg/types"
)

// Handler holds the dependencies for whitelist HTTP handlers.
type Handler struct {
	Store            *Store
	AdminPasswordB64 string
}

// HandleList handles GET /whitelist - returns all whitelisted digests.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	version, digests, err := h.Store.ListAll()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.WhitelistListResponse{
		Version: version,
		Digests: digests,
	})
}

// HandleAdd handles POST /whitelist - adds an image digest.
func (h Handler) HandleAdd(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var req types.WhitelistAddRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if err := h.Store.Add(req.Digest, req.Image); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleDelete handles DELETE /whitelist - deletes image digests atomically.
func (h Handler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var req types.WhitelistDeleteRequest
	dec := json.NewDecoder(r.Body)
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

	w.WriteHeader(http.StatusNoContent)
}

func (h Handler) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}

	token, ok := strings.CutPrefix(auth, "Basic ")
	if !ok {
		return false
	}

	return token == h.AdminPasswordB64
}
