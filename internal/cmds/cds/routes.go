package cds

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/server"
)

// dependencies bundles everything the cds router needs.
type dependencies struct {
	AttestHandler     AttestHandler
	AttestKeyHandler  attestation.Handler
	SignCSRHandler    SignCSRHandler
	AllowlistHandler  allowlist.Handler
	HandoffHandler    *issuer.HandoffHandler // nil disables /handoff (no --handoff-measurements)
	ReadyFn           attestation.ReadinessFunc
	EarIssuer         ear.Issuer
	JWKSFunc          func() []byte
	CACertPEM         []byte
	OperatorKeysPEM   []byte                // pinned operator public keys; empty = /operator-keys 404s
	RateLimiter       *issuer.IPRateLimiter // per-source-IP limiter for attestation endpoints
	MaxRequestSize    int64                 // applied to write endpoints; must be > 0
	SecretsHandler    *secrets.Handler      // nil leaves /secrets unrouted (--secrets off)
	SecretsChallenges *attestation.ChallengeStore
	SecretsOperator   *secrets.OperatorHandler       // operator-supplied values; routed with SecretsHandler
	SecretsExplain    *secrets.ExplainHandler        // release diagnostic; routed with SecretsHandler
	SecretsExternal   *secrets.ExternalConfigHandler // external-KMS config; routed with SecretsHandler
}

func newRouter(deps dependencies) http.Handler {
	if deps.MaxRequestSize <= 0 {
		panic("cds: dependencies.MaxRequestSize must be positive")
	}
	if deps.RateLimiter == nil {
		panic("cds: dependencies.RateLimiter must be set")
	}
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/readyz", attestation.HandleReadyz(deps.ReadyFn))
	r.Get("/.well-known/jwks.json", server.HandleJWKS(deps.EarIssuer, deps.JWKSFunc))
	r.Method(http.MethodGet, "/metrics", promhttp.Handler())

	r.Post("/authenticate", attestation.HandleAuthenticate(deps.AttestHandler.Challenges))
	r.Method(http.MethodPost, "/attest", deps.protected(http.HandlerFunc(deps.AttestHandler.HandleAttest)))
	r.Method(http.MethodPost, "/attest-key", deps.protected(http.HandlerFunc(deps.AttestKeyHandler.HandleAttestKey)))
	r.Method(http.MethodPost, "/sign-csr", deps.protected(http.HandlerFunc(deps.SignCSRHandler.HandleSignCSR)))

	// /handoff is mounted only when --handoff-measurements is set; a singleton
	// cds runs without it.
	if deps.HandoffHandler != nil {
		r.Method(http.MethodPost, "/handoff", deps.protected(http.HandlerFunc(deps.HandoffHandler.HandleHandoff)))
	}

	// GET is unauthenticated (RA-TLS integrity only); every mutation goes
	// through allowlistWrite (operator-JWT auth in the handler + rate limit +
	// 1 MiB body cap).
	r.Get("/allowlist", deps.AllowlistHandler.HandleList)
	r.Method(http.MethodPut, "/allowlist", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleReplaceAll)))
	r.Method(http.MethodPost, "/allowlist/digests", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleAddDigest)))
	r.Method(http.MethodDelete, "/allowlist/digests", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleDeleteDigests)))
	r.Method(http.MethodPut, "/allowlist/workloads/{name}", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandlePutWorkload)))
	r.Method(http.MethodDelete, "/allowlist/workloads/{name}", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleDeleteWorkload)))

	// GET and POST are the workload's, authenticated by mesh leaf and sandbox
	// token. PUT is the operator's, on allowlistWrite so it carries the same
	// body-bound operator token an allowlist mutation does.
	if deps.SecretsHandler != nil {
		if deps.SecretsOperator == nil || deps.SecretsExplain == nil || deps.SecretsExternal == nil {
			panic("cds: dependencies.SecretsOperator, SecretsExplain and SecretsExternal must be set alongside SecretsHandler")
		}
		r.Method(http.MethodPost, secrets.ChallengeRoute, deps.perSandbox(attestation.HandleAuthenticate(deps.SecretsChallenges)))
		r.Method(http.MethodGet, secrets.Route, deps.perSandbox(deps.SecretsHandler))
		r.Method(http.MethodPost, secrets.Route, deps.perSandbox(deps.SecretsHandler))
		r.Method(http.MethodPut, secrets.Route, deps.allowlistWrite(deps.SecretsOperator))
		r.Method(http.MethodGet, secrets.ExplainRoute, deps.allowlistWrite(deps.SecretsExplain))
		r.Method(http.MethodPut, secrets.ExternalRoute, deps.allowlistWrite(deps.SecretsExternal))
		r.Method(http.MethodGet, secrets.ExternalRoute, deps.allowlistWrite(deps.SecretsExternal))
		// POST too, so the wildcard below never sees the reserved path as a
		// store path; the handler answers 405.
		r.Method(http.MethodPost, secrets.ExternalRoute, deps.allowlistWrite(deps.SecretsExternal))
	}

	r.Get("/ca", handleCA(deps.CACertPEM))
	r.Get("/operator-keys", handleOperatorKeys(deps.OperatorKeysPEM))

	return r
}

// allowlistWriteBodyCap bounds an allowlist mutation body. A workload document
// dwarfs a digest line, so it is far larger than MaxRequestSize.
const allowlistWriteBodyCap int64 = 1 << 20

// protected wraps a write handler with per-source-IP rate limiting and the
// request-body cap. Used for the endpoints an unauthenticated caller can hit
// before any signature check: attestation issuance (each junk write costs up to
// one ECDSA verify per pinned key).
func (deps dependencies) protected(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(deps.MaxRequestSize, next))
}

// allowlistWrite is protected with the larger allowlist body cap. Its callers
// are operators reaching CDS directly, so the source address is the caller.
func (deps dependencies) allowlistWrite(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(allowlistWriteBodyCap, next))
}

// perSandbox rate-limits by the caller's attested sandbox instead of its
// address. The workload secret routes are the ones pods reach through a
// NodePort and the mesh proxy, where the address is the node's rather than the
// pod's — see secrets.RateKey.
func (deps dependencies) perSandbox(next http.Handler) http.Handler {
	return issuer.RateLimitBy(deps.RateLimiter, secrets.RateKey, capBody(deps.MaxRequestSize, next))
}

func capBody(max int64, next http.Handler) http.Handler {
	return http.MaxBytesHandler(next, max)
}

func handleCA(caCertPEM []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCertPEM)
	}
}

// handleOperatorKeys serves the pinned operator public-key bundle (public
// material, like /ca) so `c8s verify` can report which keys may mutate the
// allowlist. 404 when allowlist writes are disabled (no pinned keys).
func handleOperatorKeys(operatorKeysPEM []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if len(operatorKeysPEM) == 0 {
			http.Error(w, "no operator keys configured (allowlist writes disabled)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(operatorKeysPEM)
	}
}
