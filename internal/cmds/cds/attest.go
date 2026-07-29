package cds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
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
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

	// AllowlistStore, when set, is consulted to gate workload-digest claims:
	// every container digest a requester commits to must be allowlisted, and a
	// claim touching workload (non-floor) images must match one entry's set
	// (docs/ratls.md). nil disables workload-claims verification — a request
	// carrying claims is then rejected, since they cannot be checked.
	AllowlistStore allowlistGate

	// EARKeyProvider and EARIssuer validate the inventory EAR inside a sandbox
	// token (docs/ratls.md, "Sandbox identity") — the same JWKS/issuer pair
	// /sign-csr uses. A nil provider disables sandbox-token verification; a
	// request carrying a token is then rejected.
	EARKeyProvider issuer.KeyProvider
	EARIssuer      string
}

// allowlistGate answers the two attest-time questions: per-digest membership
// (floor OR workload) and the full document for the combination check.
// Satisfied by *internal/allowlist.Store.
type allowlistGate interface {
	Contains(digest types.Digest) (bool, error)
	LoadAll() (*pkgallowlist.Allowlist, string, error)
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
	// Workload claims (docs/ratls.md): the requester binds a
	// config-claims extension into its evidence REPORTDATA and forwards both
	// the DER and the container-digest list it commits to. Decode the DER
	// first so the SAME bytes are folded into the expected REPORTDATA below —
	// a tampered claim then fails the evidence check.
	var claimsDER []byte
	if req.WorkloadClaims != "" {
		claimsDER, err = base64.StdEncoding.DecodeString(req.WorkloadClaims)
		if err != nil {
			attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "invalid workload_claims encoding")
			return
		}
		// A stamped workload claim is downstream-verifiable only if the leaf
		// carries hardware evidence binding it. get-cert embeds a nonce-free
		// RA-TLS attestation extension into the CSR for exactly this, and
		// SignCSR copies it onto the leaf. Verify at issuance that the embedded
		// evidence actually binds these claims — fail fast here instead of
		// leaving a leaf that only fails at relying-party time (docs/ratls.md).
		if err := verifyEmbeddedClaimsBinding(csr, csrPubKey, claimsDER); err != nil {
			attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
			return
		}
	}

	// Sandbox token (docs/ratls.md, "Sandbox identity"): an inventory-signed
	// binding of the pod's sandbox ID to the requester's CSR key and this
	// request's challenge. Verified before the expensive evidence round-trip;
	// the resulting ID is stamped on the leaf only after every other check
	// passes. challengeBytes was consumed above, so a token carrying it is
	// fresh for exactly this issuance.
	var sandboxID string
	if len(req.SandboxToken) > 0 {
		sandboxID, err = h.verifySandboxToken(req.SandboxToken, csrPubKey, challengeBytes)
		if err != nil {
			slog.Warn("sandbox token rejected", "error", err)
			attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
			return
		}
	}

	expectedReportData, err := ratls.ReportDataForKeyAndClaims(csrPubKey, claimsDER, challengeBytes)
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

	// The evidence bound claimsDER (folded into expectedReportData above and
	// confirmed by VerifyEnforced), so the claims are TEE-attested. Now verify
	// the requester's init/main digest lists hash to the attested workload
	// digest and that every listed image is allowlisted, then stamp the claims
	// on the leaf so peers and `c8s verify` can read the attested workload.
	// The allowlist entry (or entries) the digest sets matched is stamped too,
	// so a verifier learns WHICH admitted policy governs this pod, not only
	// that some entry does.
	matched, err := h.verifyWorkloadClaims(claimsDER, req.InitContainerDigests, req.ContainerDigests)
	if err != nil {
		slog.Warn("workload claims rejected", "error", err)
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
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
		CSR:             csr,
		TTL:             issuer.CapTTL(h.CertTTL, issuer.MaxLeafTTL),
		Evidence:        evidenceJSON,
		ConfigClaimsExt: claimsDER,
		SandboxID:       sandboxID,
		MatchedWorkload: matched,
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
// EAR must be a CDS-issued /attest-key credential on an allowed measurement;
// the EAR's attested key must sign the token; the token's nonce must be this
// request's challenge (freshness, single-use); and its key digest must name
// the requester's CSR key — so only the key's holder can redeem it, only for
// this issuance, and only with inventory provenance.
func (h AttestHandler) verifySandboxToken(raw json.RawMessage, requesterPub crypto.PublicKey, nonce []byte) (string, error) {
	if h.EARKeyProvider == nil {
		return "", fmt.Errorf("sandbox token presented but this CDS cannot verify it")
	}
	var token workloadclaims.SignedSandboxToken
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&token); err != nil {
		return "", fmt.Errorf("decode sandbox token: %w", err)
	}
	claims, err := issuer.ValidateEARToken(token.EAR, h.EARKeyProvider, h.EARIssuer)
	if err != nil {
		return "", fmt.Errorf("inventory EAR invalid: %w", err)
	}
	// Same pinning semantics as the /attest evidence check above:
	// CheckMeasurement is a no-op with empty Measurements (UNSAFE outside dev).
	if err := issuer.CheckMeasurement(claims, h.Measurements, "attest sandbox-token"); err != nil {
		return "", fmt.Errorf("inventory EAR measurement not allowed")
	}
	inventoryPub, err := issuer.AttestedECDSAKey(claims)
	if err != nil {
		return "", fmt.Errorf("inventory EAR key: %w", err)
	}
	// Freshness is the challenge itself: the token must carry the same nonce
	// CDS is consuming for this request, so it cannot be replayed against a
	// later request or pre-signed against a future one.
	sandboxID, err := token.Verify(inventoryPub, requesterPub, nonce)
	if err != nil {
		return "", err
	}
	if err := ratls.ValidateSandboxID(sandboxID); err != nil {
		return "", err
	}
	return sandboxID, nil
}

// verifyEmbeddedClaimsBinding fails closed unless the CSR carries an RA-TLS
// attestation extension whose evidence binds the config-claims (docs/ratls.md).
// SignCSR copies that extension onto the leaf; if it is absent — or binds
// different claims — the leaf's config-claims could never verify against the
// evidence at a relying party. For SEV-SNP the REPORTDATA is compared locally
// (no attestation-api call); envelope evidence (az-snp/TDX) has no in-process
// parser, so it is accepted on presence and its binding is proven at
// relying-party time.
func verifyEmbeddedClaimsBinding(csr *x509.CertificateRequest, pub crypto.PublicKey, claimsDER []byte) error {
	extValue := csrRATLSExtensionValue(csr)
	if extValue == nil {
		return fmt.Errorf("workload claims require an embedded RA-TLS attestation extension on the CSR")
	}
	att, err := ratls.UnmarshalExtension(extValue)
	if err != nil {
		return fmt.Errorf("embedded RA-TLS attestation does not parse: %w", err)
	}
	expected, err := ratls.ReportDataForKeyAndClaims(pub, claimsDER, nil)
	if err != nil {
		return err
	}
	if reportData, ok := att.ReportData(); ok && !bytes.Equal(reportData[:sha512.Size384], expected[:sha512.Size384]) {
		return fmt.Errorf("embedded RA-TLS evidence does not bind the config-claims")
	}
	return nil
}

// csrRATLSExtensionValue returns the value of the CSR's RA-TLS attestation
// extension (the one SignCSR copies onto the leaf), or nil when absent.
func csrRATLSExtensionValue(csr *x509.CertificateRequest) []byte {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(ratls.OIDRATLSAttestation) {
			return ext.Value
		}
	}
	return nil
}

// verifyWorkloadClaims checks that the requester's container-digest list matches
// the attested workload digest, that every listed image is allowlisted, and —
// when any listed image is a workload (non-floor) image — that the claimed
// init/main set exactly matches one workload entry, so containers from different
// entries cannot be mixed into an unauthorized pod (docs/ratls.md). claimsDER
// nil ⇒ nothing to verify; it fails closed if claims are present with no store.
//
// On success it returns the matched workload entries for stamping (nil for a
// claims-free or floor-only request). The match is over image digests only —
// argv never reaches CDS — so entries sharing digest sets and differing only in
// argv policy all match, and the stamp names the whole set rather than
// asserting an identity the digests do not establish
// (pkg/ratls/matchedworkload.go).
func (h AttestHandler) verifyWorkloadClaims(claimsDER []byte, initDigests, mainDigests []string) (*ratls.MatchedWorkload, error) {
	if len(claimsDER) == 0 {
		return nil, nil
	}
	if h.AllowlistStore == nil {
		return nil, fmt.Errorf("workload claims presented but this CDS cannot verify them")
	}
	if _, err := workloadclaims.VerifyWorkloadDigest(claimsDER, initDigests, mainDigests); err != nil {
		return nil, err
	}
	for _, d := range append(append([]string{}, initDigests...), mainDigests...) {
		digest, err := types.ParseDigest(d)
		if err != nil {
			return nil, fmt.Errorf("container digest %q: %w", d, err)
		}
		allowed, err := h.AllowlistStore.Contains(digest)
		if err != nil {
			return nil, fmt.Errorf("check allowlist: %w", err)
		}
		if !allowed {
			return nil, fmt.Errorf("container image %s is not allowlisted", digest)
		}
	}
	doc, _, err := h.AllowlistStore.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}
	return matchWorkloadEntries(doc, initDigests, mainDigests)
}

// matchWorkloadEntries requires the non-floor portion of the claimed init/main
// sets to equal at least one workload entry's non-floor init/main sets, and
// returns the matched entries plus their canonical digest for stamping.
//
// Floor digests are excluded from both sides: they are admitted alone and carry
// no combination policy. Injected c8s containers (get-cert) are floor entries,
// so their measured digest drops out here — that floor pin is the exclusion
// (name-based exclusion happens upstream at the inventory, before CDS sees only
// digests). A floor-only pod matches no entry and is stamped with nothing.
func matchWorkloadEntries(doc *pkgallowlist.Allowlist, initDigests, mainDigests []string) (*ratls.MatchedWorkload, error) {
	names := doc.MatchingWorkloadEntries(initDigests, mainDigests)
	if len(names) == 0 {
		// Distinguish "nothing to match" (floor-only pod) from "no entry
		// matches" — the first admits with no stamp, the second refuses.
		if floorOnly(doc, initDigests, mainDigests) {
			return nil, nil
		}
		return nil, fmt.Errorf("claimed container set matches no single workload entry")
	}
	digest, err := doc.WorkloadEntriesDigest(names)
	if err != nil {
		return nil, fmt.Errorf("digest matched workload entries: %w", err)
	}
	return &ratls.MatchedWorkload{Names: names, EntriesDigest: digest}, nil
}

// floorOnly reports whether every claimed digest is a floor entry (or
// unparseable, which upstream validation has already excluded).
func floorOnly(doc *pkgallowlist.Allowlist, initDigests, mainDigests []string) bool {
	for _, d := range append(append([]string{}, initDigests...), mainDigests...) {
		parsed, err := types.ParseDigest(d)
		if err != nil {
			continue
		}
		if _, isFloor := doc.Digests[parsed.String()]; !isFloor {
			return false
		}
	}
	return true
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
