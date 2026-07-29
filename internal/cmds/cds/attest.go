package cds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// AttestHandler serves POST /attest by verifying TEE evidence and signing the
// requester's CSR in-process — attestation and mesh-CA signing live in the same
// binary, so there is no EAR JWT round-trip to a separate signer.
//
// THREAT MODEL: the measurement check is the only thing standing between an
// attacker who controls a TEE workload and a CA-signed leaf for any subject
// they choose. Empty Measurements skips this check (UNSAFE outside dev).
type AttestHandler struct {
	Challenges        *attestation.ChallengeStore
	AttestationClient attestationclient.Client
	CA                *issuer.CA
	CAChainPEM        []byte
	CertTTL           time.Duration

	// RequestTimeout caps how long /attest may spend on attestation
	// verification + signing. Zero = no timeout.
	RequestTimeout time.Duration

	// Measurements is the flat allowlist of SHA-384 launch digests permitted
	// to obtain a signed leaf. Empty = no measurement pinning.
	Measurements map[string]bool

	// Policy enforces SAN/CN constraints on the CSR before signing. Without
	// this, an attestation-passing workload could mint a leaf for any
	// subject — see THREAT MODEL on issuer.CA.SignCSR.
	Policy issuer.CSRPolicy

	// SANValidation, when true, binds Policy.SourceIP to the request's
	// RemoteAddr at handler time. When false, Policy.SourceIP stays empty and
	// ValidateCSR rejects any CSR carrying IP SANs.
	SANValidation bool

	// AllowlistStore, when set, gates a sandbox's running images: every image
	// the inventory reports must be allowlisted (docs/ratls.md). nil rejects any
	// request carrying a sandbox token, since it could not be checked.
	AllowlistStore allowlistGate

	// SandboxDigests resolves a sandbox's inventory: its signing key and what
	// the sandbox is running, over mutually-attested RA-TLS to a privileged
	// port. nil rejects any request carrying a sandbox token, for the same
	// reason as a nil AllowlistStore.
	SandboxDigests sandboxDigestSource

	// InventoryHosts bounds which addresses the callback may dial — the
	// operator's node CIDRs. Empty rejects any request carrying a sandbox
	// token: without it a workload could point CDS at its own pod IP and
	// answer as the inventory.
	InventoryHosts workloadclaims.InventoryHosts
}

// sandboxDigestSource is the inventory callback, satisfied by
// *workloadclaims.DigestsClient. An interface so tests can drive issuance
// without standing up an RA-TLS inventory.
type sandboxDigestSource interface {
	InventoryKey(ctx context.Context, host string) (*ecdsa.PublicKey, error)
	Fetch(ctx context.Context, host, sandboxID string) ([]string, error)
}

// allowlistGate answers the one attest-time question: is this digest admitted
// at all, as a floor entry or as any workload container. Satisfied by
// *internal/allowlist.Store.
type allowlistGate interface {
	Contains(digest types.Digest) (bool, error)
}

func (h AttestHandler) HandleAttest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.RequestTimeout)
		defer cancel()
	}

	var req types.AttestRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}
	if !h.Challenges.Consume(challengeBytes) {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}

	csr, err := attestation.ParseAndVerifyCSR(req.CSR)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}
	csrPubKey, err := attestation.ECDSAPublicKeyFromCSR(csr)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}
	// Sandbox token (docs/ratls.md, "Sandbox identity"): an inventory-signed
	// binding of the pod's sandbox ID — and of the inventory to ask about it —
	// to the requester's CSR key and this request's challenge. Verified before
	// the expensive evidence round-trip; the resulting ID is stamped on the
	// leaf only after every other check passes. challengeBytes was consumed
	// above, so a token carrying it is fresh for exactly this issuance.
	var sandbox workloadclaims.VerifiedSandbox
	if len(req.SandboxToken) > 0 {
		sandbox, err = h.verifySandboxToken(ctx, req.SandboxToken, csrPubKey, challengeBytes)
		if err != nil {
			slog.Warn("sandbox token rejected", "error", err)
			attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
			return
		}
	}

	expectedReportData, err := ratls.ReportDataForKey(csrPubKey, challengeBytes)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}

	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			fmt.Sprintf("invalid evidence: %s", err))
		return
	}

	reportData := types.NewBase64Bytes(expectedReportData[:sha512.Size384])
	verifyReq := types.VerifyReportData(req.Evidence, reportData)
	verifyResp, err := h.AttestationClient.VerifyEnforced(ctx, verifyReq)
	if err != nil {
		status, code, msg := classifyVerifyError(err)
		slog.Warn("attestation verification failed", "status", status, "error", err)
		attestation.WriteError(w, status, code, msg)
		return
	}

	if len(h.Measurements) > 0 {
		digest := strings.ToLower(verifyResp.Result.Claims.LaunchDigest)
		if !h.Measurements[digest] {
			slog.Warn("measurement not in allowlist", "launch_digest", digest)
			attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "launch measurement not allowed")
			return
		}
	}

	policy := h.Policy
	if h.SANValidation {
		policy.SourceIP = issuer.SourceIPFromRemoteAddr(r.RemoteAddr)
	}
	if err := issuer.ValidateCSR(csr, policy); err != nil {
		slog.Warn("CSR validation failed", "error", err, "remote_addr", r.RemoteAddr)
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
		return
	}

	// The token proved which sandbox the requester is in and named the
	// inventory that admitted it. Ask that inventory what the sandbox is
	// actually running and gate issuance on the allowlist. The requester never
	// gets a say in the answer.
	if err := h.verifySandboxWorkload(ctx, sandbox); err != nil {
		// The detail stays in the log. A requester picks both the sandbox ID and
		// the address CDS just dialled, so echoing what happened there would
		// hand it a reachability oracle for CDS's network position.
		slog.Warn("sandbox workload rejected",
			"sandbox_id", sandbox.SandboxID, "inventory_addr", sandbox.InventoryHost, "error", err)
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, "sandbox workload not authorized")
		return
	}

	if ctx.Err() != nil {
		attestation.WriteError(w, http.StatusGatewayTimeout, types.ErrorCodeTimeout, "request timeout")
		return
	}

	// The leaf's OID .1.1 RA-TLS extension is copied from the client's CSR
	// (see issuer.SignCSR): the client embeds evidence bound to
	// SHA-384(pubkey) with no nonce, which is the only form downstream
	// ratls-mode verifiers (secret-inventory --peer-verify=ratls) can re-verify.
	// The challenge-bound evidence verified above proves freshness at
	// issuance but is NOT embeddable — its REPORTDATA includes the consumed
	// challenge, so re-verification against the bare key would always fail.
	certPEM, _, err := h.CA.SignCSR(issuer.SignCSRParams{
		CSR:       csr,
		TTL:       issuer.CapTTL(h.CertTTL, issuer.MaxLeafTTL),
		Evidence:  evidenceJSON,
		SandboxID: sandbox.SandboxID,
	})
	if err != nil {
		slog.Error("in-process sign failed", "error", err)
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, err.Error())
		return
	}
	caChainPEM := h.caChainPEM()
	if len(caChainPEM) == 0 {
		slog.Error("in-process sign failed: CA chain unavailable")
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, "CA chain unavailable")
		return
	}

	slog.Info("certificate issued (in-process)", "cn", csr.Subject.CommonName)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(slices.Concat(certPEM, caChainPEM))
}

// verifySandboxToken verifies an inventory-signed sandbox token and returns its
// sandbox ID. The chain (docs/ratls.md, "Sandbox identity"): the envelope's
// signing key is fetched from the inventory's own endpoint on a node address
// the operator configured; that key must sign the token; the token's nonce must
// be this request's challenge (freshness, single-use); and its key digest must
// name the requester's CSR key — so only the key's holder can redeem it, only
// for this issuance, and only with inventory provenance.
func (h AttestHandler) verifySandboxToken(ctx context.Context, raw json.RawMessage, requesterPub crypto.PublicKey, nonce []byte) (workloadclaims.VerifiedSandbox, error) {
	if h.SandboxDigests == nil {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox token presented but this CDS cannot reach an inventory to verify it")
	}
	if len(h.InventoryHosts) == 0 {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox token presented but no inventory CIDRs are configured to bound the callback")
	}
	var token workloadclaims.SignedSandboxToken
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&token); err != nil {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("decode sandbox token: %w", err)
	}

	// The host says which endpoint holds the key that would verify the
	// signature, so it has to be read before verification can happen. Nothing
	// is trusted on its basis: it only selects a dial target, which must be a
	// node address the operator configured — a pod IP is never dialed, so a
	// workload cannot stand in for its node's inventory. A wrong host simply
	// yields a key the signature fails under.
	host, err := workloadclaims.UnverifiedInventoryHost(token.Token)
	if err != nil {
		return workloadclaims.VerifiedSandbox{}, err
	}
	if !h.InventoryHosts.Contains(host) {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("sandbox token names an inventory outside the configured node CIDRs")
	}
	// The key comes from the inventory's own endpoint on a privileged port,
	// which is what separates the inventory from a compromised workload in the
	// same node: an unprivileged pod cannot bind the node's network namespace
	// (the chart's deny-host-namespaces policy). Measurement alone cannot make
	// that distinction on node-CVM, where every pod shares the node's.
	inventoryPub, err := h.SandboxDigests.InventoryKey(ctx, host)
	if err != nil {
		return workloadclaims.VerifiedSandbox{}, fmt.Errorf("resolve inventory key: %w", err)
	}
	// Freshness is the challenge itself: the token must carry the same nonce
	// CDS is consuming for this request, so it cannot be replayed against a
	// later request or pre-signed against a future one.
	sandbox, err := token.Verify(inventoryPub, requesterPub, nonce)
	if err != nil {
		return workloadclaims.VerifiedSandbox{}, err
	}
	if err := ratls.ValidateSandboxID(sandbox.SandboxID); err != nil {
		return workloadclaims.VerifiedSandbox{}, err
	}
	return sandbox, nil
}

// verifySandboxWorkload asks the sandbox's own inventory which images it is
// running and requires every one of them to be allowlisted before issuing
// (docs/ratls.md, "Sandbox identity").
//
// Membership only. It deliberately does NOT require the running set to match a
// whole workload entry: issuance happens at arbitrary points in the pod
// lifecycle — while a user init container runs, between main containers coming
// up, while one restarts, and after completed init containers are reaped — and
// in every one of those the running set is a strict subset of what the pod
// declares. Gating on the whole set would deny certificates for ordinary
// lifecycle states, permanently so for pods with init containers. Membership is
// subset-safe: any subset of an allowlisted set is still allowlisted.
//
// Whole-set enforcement belongs where the pod is complete and the stake is
// high — secrets release — not at cert issuance. Until then a leaf's sandbox ID
// says "this key belongs to pod X", not "pod X runs exactly workload Y".
//
// No sandbox ⇒ nothing to check: a requester that presents no token gets a leaf
// with no sandbox ID. With a token, an unreachable inventory or a
// non-allowlisted image is fail-closed — CDS cannot establish what the pod
// runs, or has established that it should not run.
func (h AttestHandler) verifySandboxWorkload(ctx context.Context, sandbox workloadclaims.VerifiedSandbox) error {
	if sandbox.SandboxID == "" {
		return nil
	}
	if h.AllowlistStore == nil {
		return fmt.Errorf("sandbox token presented but this CDS has no allowlist to check it against")
	}
	if h.SandboxDigests == nil {
		return fmt.Errorf("sandbox token presented but this CDS cannot reach the inventory for its digests")
	}
	digests, err := h.SandboxDigests.Fetch(ctx, sandbox.InventoryHost, sandbox.SandboxID)
	if err != nil {
		return fmt.Errorf("resolve sandbox digests from %s: %w", sandbox.InventoryHost, err)
	}
	if len(digests) == 0 {
		// "No containers" is not "nothing to check" — it is no evidence at all,
		// and looping over it would pass the gate vacuously. A sandbox always
		// runs at least the sidecar that is asking, so an empty answer means
		// the inventory is still syncing (or is lying), both of which must wait.
		return fmt.Errorf("inventory reports no containers in sandbox %s", sandbox.SandboxID)
	}
	for _, d := range digests {
		digest, err := types.ParseDigest(d)
		if err != nil {
			return fmt.Errorf("container digest %q: %w", d, err)
		}
		allowed, err := h.AllowlistStore.Contains(digest)
		if err != nil {
			return fmt.Errorf("check allowlist: %w", err)
		}
		if !allowed {
			return fmt.Errorf("container image %s is not allowlisted", digest)
		}
	}
	return nil
}

func (h AttestHandler) caChainPEM() []byte {
	if len(h.CAChainPEM) > 0 {
		return h.CAChainPEM
	}
	if h.CA == nil || h.CA.Cert == nil {
		return nil
	}
	return certutil.EncodeCertPEM(h.CA.Cert.Raw)
}

// classifyVerifyError maps a VerifyEnforced error to (HTTP status, error code,
// message). A rejected verdict — bad signature, REPORTDATA mismatch, or a 4xx
// the attestation-api returns for malformed/unacceptable evidence — is the
// caller's fault and must not be reported as attestation_api_unreachable.
// Only a transport failure or a 5xx/garbage upstream response is a real outage.
// Upstream 408 (timeout) and 429 (rate-limited) are retryable availability
// conditions, not evidence rejections, so they classify as unreachable too.
func classifyVerifyError(err error) (int, string, string) {
	switch {
	case errors.Is(err, attestationclient.ErrSignatureInvalid):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "attestation signature invalid"
	case errors.Is(err, attestationclient.ErrReportDataMismatch):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "challenge mismatch in attestation evidence"
	}
	var apiErr *attestationclient.APIError
	if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 &&
		apiErr.Status != http.StatusRequestTimeout && apiErr.Status != http.StatusTooManyRequests {
		return http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "attestation evidence rejected by attestation-api"
	}
	return http.StatusBadGateway, types.ErrorCodeAttestationApiUnreachable,
		fmt.Sprintf("failed to reach attestation-api: %s", err)
}
