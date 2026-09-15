package credrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// AttestPath serves operator-authorized, nonce-bound bootstrap evidence.
const AttestPath = "/attest"

const attestTimeout = 30 * time.Second

// AttestRequest supplies a fresh 32-byte nonce, encoded as base64 in JSON.
// The operator token must authorize these exact request bytes.
type AttestRequest struct {
	Nonce []byte `json:"nonce"`
}

// serveAttest is reached only after ServeHTTP authorizes the request.
func (h *Handler) serveAttest(w http.ResponseWriter, r *http.Request, body []byte) {
	var req AttestRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF || len(req.Nonce) != 32 {
		http.Error(w, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if h.generateEvidence == nil {
		http.Error(w, "attestation unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), attestTimeout)
	defer cancel()
	evidence, err := h.generateEvidence(ctx, req.Nonce)
	if err != nil {
		http.Error(w, "attestation unavailable", http.StatusBadGateway)
		return
	}
	response, err := json.Marshal(evidence)
	if err != nil {
		http.Error(w, "attestation unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(response)
}
