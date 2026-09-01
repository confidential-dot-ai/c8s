package teewebpki

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	Route            = "/tee-webpki/state"
	CSRRoute         = "/tee-webpki/csr"
	CertificateRoute = "/tee-webpki/certificate"
)

// ServeCSR publishes only the CSR. It never returns either private seed.
func (h Handler) ServeCSR(w http.ResponseWriter, _ *http.Request) {
	if h.Store == nil {
		http.Error(w, "tee-webpki is not configured", http.StatusServiceUnavailable)
		return
	}
	state := h.Store.Snapshot()
	if len(state.CSRPEM) == 0 {
		http.Error(w, "tee-webpki CSR is not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs10")
	w.Write(state.CSRPEM)
}

// Handler releases protected TLS state only to the expected admitted tls-lb
// workload. CDS TLS verifies the client chain before this check.
type Handler struct {
	Store            *Store
	ExpectedWorkload string
}

// OperatorHandler accepts only public certificate and ACME state. The
// operator authorization is bound to the exact request body.
type OperatorHandler struct {
	Store     *Store
	Authorize func(*http.Request, []byte) error
}

func (h OperatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil || h.Authorize == nil {
		http.Error(w, "tee-webpki certificate updates are disabled", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		http.Error(w, "bad request: certificate update is too large", http.StatusBadRequest)
		return
	}
	if err := h.Authorize(r, body); err != nil {
		http.Error(w, "unauthorized certificate update", http.StatusUnauthorized)
		return
	}
	var update PublicUpdate
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&update); err != nil || len(update.CertificatePEM) == 0 || len(update.CSRPEM) != 0 {
		http.Error(w, "bad request: version and certificate_pem are required", http.StatusBadRequest)
		return
	}
	state, err := h.Store.UpdatePublicState(update)
	if err != nil {
		if update.Version != h.Store.Snapshot().Version {
			http.Error(w, "conflict: stale TLS state version", http.StatusConflict)
			return
		}
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Version uint64 `json:"version"`
	}{Version: state.Version})
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil || !allowlist.ValidWorkloadName(h.ExpectedWorkload) {
		http.Error(w, "tee-webpki is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := h.authorize(r); err != nil {
		http.Error(w, "forbidden: caller is not the admitted tls-lb workload", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(h.Store.Snapshot())
	case http.MethodPut:
		var update PublicUpdate
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&update); err != nil {
			http.Error(w, "bad request: invalid public TLS state", http.StatusBadRequest)
			return
		}
		state, err := h.Store.UpdatePublicState(update)
		if err != nil {
			if state := h.Store.Snapshot(); update.Version != state.Version {
				http.Error(w, "conflict: stale TLS state version", http.StatusConflict)
				return
			}
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Version uint64 `json:"version"`
		}{Version: state.Version})
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h Handler) authorize(r *http.Request) error {
	if r.TLS == nil {
		return fmt.Errorf("request has no TLS state")
	}
	matched, err := ratls.PeerMatchedWorkload(*r.TLS)
	if err != nil {
		return err
	}
	if matched == nil || matched.EffectiveIdentity() != h.ExpectedWorkload {
		return fmt.Errorf("matched workload does not equal %q", h.ExpectedWorkload)
	}
	return nil
}
