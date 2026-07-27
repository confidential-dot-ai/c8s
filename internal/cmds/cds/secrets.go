package cds

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/secretstore"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// SecretsHandler serves the secrets broker: POST /secrets/fetch for attested
// workloads, GET /secrets/broker-identity for clients anchoring the broker,
// and the operator deposit routes. The release gate mirrors /attest
// (docs/secrets-broker.md).
type SecretsHandler struct {
	Challenges        *attestation.ChallengeStore
	AttestationClient attestationclient.Client
	// RequestTimeout caps one fetch's attestation round-trip. Zero = none.
	RequestTimeout time.Duration
	// Measurements pins which launch digests may fetch. Unlike /attest, an
	// empty map FAILS CLOSED: secrets degrade silently where a fake-issued
	// cert fails loudly at first mesh use.
	Measurements   map[string]bool
	AllowlistStore allowlistGate
	Store          secretstore.Store
	Identity       *brokerIdentity
	// WriteAuthorizer authorizes operator deposits (operatorauth), nil = off.
	WriteAuthorizer func(r *http.Request, body []byte) error
}

// operatorWriteBodyCap bounds a deposit body — the same 1 MiB as allowlist writes.
const operatorWriteBodyCap int64 = 1 << 20

var secretsFetchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "c8s_cds_secrets_fetch_total",
	Help: "Secrets broker fetch decisions by result.",
}, []string{"result"})

var secretsOperatorTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "c8s_cds_secrets_operator_total",
	Help: "Secrets broker operator deposit decisions by operation and result.",
}, []string{"op", "result"})

// HandleBrokerIdentity serves GET /secrets/broker-identity. Unauthenticated
// like /ca: integrity comes from the chain to the mesh CA, which the client
// anchors out of band (the pod's get-cert bundle).
func (h SecretsHandler) HandleBrokerIdentity(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.Identity.doc)
}

// HandleFetch serves POST /secrets/fetch: the attestation-gated release of the
// calling pod's entitled secrets, wrapped to its evidence-bound response key
// and signed by the broker identity.
func (h SecretsHandler) HandleFetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.RequestTimeout)
		defer cancel()
	}

	var req secrets.FetchRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		secretsFetchTotal.WithLabelValues("invalid_request").Inc()
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil || !h.Challenges.Consume(challengeBytes) {
		secretsFetchTotal.WithLabelValues("invalid_challenge").Inc()
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}

	responsePub, err := base64.StdEncoding.DecodeString(req.ResponsePubkey)
	if err != nil || len(responsePub) != 32 {
		secretsFetchTotal.WithLabelValues("invalid_request").Inc()
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			"response_pubkey must be a base64 raw X25519 public key")
		return
	}

	expectedReportData, err := secrets.ReportDataForFetch(challengeBytes, req)
	if err != nil {
		secretsFetchTotal.WithLabelValues("invalid_request").Inc()
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	verifyResp, err := h.AttestationClient.VerifyEnforced(ctx, secrets.VerifyReportData(req.Evidence, expectedReportData))
	if err != nil {
		status, code, msg := classifyVerifyError(err)
		slog.Warn("secrets fetch: attestation verification failed", "status", status, "error", err)
		secretsFetchTotal.WithLabelValues("verification_failed").Inc()
		attestation.WriteError(w, status, code, msg)
		return
	}

	if len(h.Measurements) == 0 {
		slog.Error("secrets fetch rejected: no measurements pinned", "remote", r.RemoteAddr)
		secretsFetchTotal.WithLabelValues("measurement_not_configured").Inc()
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementNotConfigured,
			"secrets fetch requires cds.measurements to pin at least one launch digest")
		return
	}
	launchDigest := strings.ToLower(verifyResp.Result.Claims.LaunchDigest)
	if !h.Measurements[launchDigest] {
		slog.Warn("secrets fetch: measurement not in allowlist", "launch_digest", launchDigest)
		secretsFetchTotal.WithLabelValues("measurement_denied").Inc()
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "launch measurement not allowed")
		return
	}

	doc, _, err := h.AllowlistStore.LoadAll()
	if err != nil {
		slog.Error("secrets fetch: load allowlist", "error", err)
		secretsFetchTotal.WithLabelValues("internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "allowlist unavailable")
		return
	}
	matches := resolveEntries(doc, req.InitContainerDigests, req.ContainerDigests)
	if len(matches) == 0 {
		slog.Warn("secrets fetch: claimed container set matches no workload entry",
			"init", req.InitContainerDigests, "main", req.ContainerDigests)
		secretsFetchTotal.WithLabelValues("grant_denied").Inc()
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeGrantDenied,
			"claimed container set matches no workload entry")
		return
	}
	if len(matches) > 1 {
		// Identical-set entries are one security domain, but the store scopes
		// values by entry name — answering would pick one silently. Fail loud.
		slog.Warn("secrets fetch: ambiguous workload entry", "matches", matches)
		secretsFetchTotal.WithLabelValues("entry_ambiguous").Inc()
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeEntryAmbiguous,
			fmt.Sprintf("claimed container set matches multiple workload entries: %s", strings.Join(matches, ", ")))
		return
	}
	entryName := matches[0]
	entry := doc.Workloads[entryName]

	values := map[string]string{}
	for _, sr := range req.Requests {
		digest, err := types.ParseDigest(sr.Digest)
		if err != nil {
			secretsFetchTotal.WithLabelValues("invalid_request").Inc()
			attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
			return
		}
		if !entryHasDigest(&entry, digest) {
			slog.Warn("secrets fetch: digest not in resolved entry", "entry", entryName, "digest", digest)
			secretsFetchTotal.WithLabelValues("grant_denied").Inc()
			attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeGrantDenied,
				fmt.Sprintf("digest %s is not in workload entry %q", digest, entryName))
			return
		}
		for _, p := range sr.Paths {
			if err := validRequestPath(p); err != nil {
				secretsFetchTotal.WithLabelValues("invalid_request").Inc()
				attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
				return
			}
			if !grantFor(&entry, digest, p, false) {
				slog.Warn("secrets fetch: path not granted", "entry", entryName, "digest", digest, "path", p)
				secretsFetchTotal.WithLabelValues("grant_denied").Inc()
				attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeGrantDenied,
					fmt.Sprintf("path %q is not granted to %s in workload entry %q", p, digest, entryName))
				return
			}
			value, err := h.Store.Get(ctx, secretstore.Ref{Entry: entryName, Path: p}, digest)
			if errors.Is(err, secretstore.ErrNotFound) {
				secretsFetchTotal.WithLabelValues("not_found").Inc()
				attestation.WriteError(w, http.StatusNotFound, types.ErrorCodeSecretNotFound,
					fmt.Sprintf("no secret at %q in workload entry %q", p, entryName))
				return
			}
			if err != nil {
				slog.Error("secrets fetch: store get", "entry", entryName, "path", p, "error", err)
				secretsFetchTotal.WithLabelValues("internal").Inc()
				attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "store error")
				return
			}
			values[p] = base64.StdEncoding.EncodeToString(value)
		}
	}

	payloadJSON, err := json.Marshal(values)
	if err != nil {
		secretsFetchTotal.WithLabelValues("internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "marshal response")
		return
	}
	payload, err := secrets.Wrap(responsePub, payloadJSON, []byte(secrets.FetchAAD))
	if err != nil {
		slog.Error("secrets fetch: wrap response", "error", err)
		secretsFetchTotal.WithLabelValues("internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "wrap response")
		return
	}
	signature, err := secrets.SignResponse(h.Identity.signingKey, payload)
	if err != nil {
		secretsFetchTotal.WithLabelValues("internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "sign response")
		return
	}

	var totalBytes int
	for _, v := range values {
		totalBytes += len(v)
	}
	slog.Info("secrets released",
		"entry", entryName,
		"launch_digest", launchDigest,
		"paths", len(values),
		"value_bytes", totalBytes,
		"remote", r.RemoteAddr,
	)
	secretsFetchTotal.WithLabelValues("released").Inc()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets.FetchResponse{Payload: payload, Signature: signature})
}

// HandleOperatorPut serves PUT /secrets/entries/{entry}/paths/* : deposit a
// secret, wrapped to the broker encryption key. Operator-JWT authorized.
func (h SecretsHandler) HandleOperatorPut(w http.ResponseWriter, r *http.Request) {
	entry, p := chi.URLParam(r, "entry"), "/"+chi.URLParam(r, "*")
	body, ok := h.authorizeOperator(w, r)
	if !ok {
		return
	}
	var req secrets.Wrapped
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		secretsOperatorTotal.WithLabelValues("put", "invalid_request").Inc()
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	if err := h.checkEntry(entry, p); err != nil {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}
	value, err := secrets.Unwrap(h.Identity.encPriv, secrets.DepositAAD(entry, p), req)
	if err != nil {
		slog.Warn("secrets deposit: unwrap failed", "entry", entry, "path", p, "remote", r.RemoteAddr)
		secretsOperatorTotal.WithLabelValues("put", "unwrap_failed").Inc()
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "value does not unwrap for this broker")
		return
	}
	if err := h.Store.Set(r.Context(), secretstore.Ref{Entry: entry, Path: p}, value); err != nil {
		slog.Error("secrets deposit: store set", "entry", entry, "path", p, "error", err)
		secretsOperatorTotal.WithLabelValues("put", "internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "store error")
		return
	}
	slog.Info("secret deposited", "entry", entry, "path", p, "value_bytes", len(value), "remote", r.RemoteAddr)
	secretsOperatorTotal.WithLabelValues("put", "ok").Inc()
	w.WriteHeader(http.StatusNoContent)
}

// HandleOperatorGet serves GET /secrets/entries/{entry}/paths/*?pubkey= :
// operator read-back, wrapped to the ephemeral key in the query.
func (h SecretsHandler) HandleOperatorGet(w http.ResponseWriter, r *http.Request) {
	entry, p := chi.URLParam(r, "entry"), "/"+chi.URLParam(r, "*")
	if _, ok := h.authorizeOperator(w, r); !ok {
		return
	}
	pub, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("pubkey"))
	if err != nil || len(pub) != 32 {
		secretsOperatorTotal.WithLabelValues("get", "invalid_request").Inc()
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			"pubkey query parameter must be a base64 raw X25519 public key")
		return
	}
	value, err := h.Store.Get(r.Context(), secretstore.Ref{Entry: entry, Path: p}, types.Digest{})
	if errors.Is(err, secretstore.ErrNotFound) {
		secretsOperatorTotal.WithLabelValues("get", "not_found").Inc()
		attestation.WriteError(w, http.StatusNotFound, types.ErrorCodeSecretNotFound, "no secret at this path")
		return
	}
	if err != nil {
		slog.Error("secrets read-back: store get", "entry", entry, "path", p, "error", err)
		secretsOperatorTotal.WithLabelValues("get", "internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "store error")
		return
	}
	wrapped, err := secrets.Wrap(pub, value, secrets.DepositAAD(entry, p))
	if err != nil {
		secretsOperatorTotal.WithLabelValues("get", "internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "wrap response")
		return
	}
	// Sign like a fetch response: the wrap alone only proves the sender knew
	// the public encryption key; the signature is what a fake broker cannot mint.
	signature, err := secrets.SignResponse(h.Identity.signingKey, wrapped)
	if err != nil {
		secretsOperatorTotal.WithLabelValues("get", "internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "sign response")
		return
	}
	slog.Info("secret read back", "entry", entry, "path", p, "value_bytes", len(value), "remote", r.RemoteAddr)
	secretsOperatorTotal.WithLabelValues("get", "ok").Inc()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets.FetchResponse{Payload: wrapped, Signature: signature})
}

// HandleOperatorDelete serves DELETE /secrets/entries/{entry}/paths/* .
func (h SecretsHandler) HandleOperatorDelete(w http.ResponseWriter, r *http.Request) {
	entry, p := chi.URLParam(r, "entry"), "/"+chi.URLParam(r, "*")
	if _, ok := h.authorizeOperator(w, r); !ok {
		return
	}
	if err := h.Store.Delete(r.Context(), secretstore.Ref{Entry: entry, Path: p}); err != nil {
		slog.Error("secrets delete: store delete", "entry", entry, "path", p, "error", err)
		secretsOperatorTotal.WithLabelValues("delete", "internal").Inc()
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeInternal, "store error")
		return
	}
	slog.Info("secret deleted", "entry", entry, "path", p, "remote", r.RemoteAddr)
	secretsOperatorTotal.WithLabelValues("delete", "ok").Inc()
	w.WriteHeader(http.StatusNoContent)
}

// authorizeOperator gates an operator mutation on the pinned-key JWT, the same
// shape as allowlist writes.
func (h SecretsHandler) authorizeOperator(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if h.WriteAuthorizer == nil {
		attestation.WriteError(w, http.StatusUnauthorized, types.ErrorCodeInvalidToken, "operator writes disabled")
		return nil, false
	}
	body, ok := httputil.ReadCappedBody(w, r, operatorWriteBodyCap)
	if !ok {
		return nil, false
	}
	if err := h.WriteAuthorizer(r, body); err != nil {
		slog.Warn("secrets operator write rejected", "method", r.Method, "remote", r.RemoteAddr, "reason", err)
		attestation.WriteError(w, http.StatusUnauthorized, types.ErrorCodeInvalidToken, "operator authorization failed")
		return nil, false
	}
	return body, true
}

// checkEntry validates a deposit destination: the workload entry must exist
// and the path must be a well-formed request path.
func (h SecretsHandler) checkEntry(entry, p string) error {
	if entry == "" {
		return fmt.Errorf("entry is required")
	}
	doc, _, err := h.AllowlistStore.LoadAll()
	if err != nil {
		return fmt.Errorf("load allowlist: %w", err)
	}
	if _, ok := doc.Workloads[entry]; !ok {
		return fmt.Errorf("workload entry %q does not exist", entry)
	}
	return validRequestPath(p)
}
