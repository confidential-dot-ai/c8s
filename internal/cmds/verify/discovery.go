package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// defaultDiscoveryPath is the path the tls-lb serves its discovery document on.
const defaultDiscoveryPath = "/v1/discovery"

// gatherFromDiscovery fetches the tls-lb discovery document and builds evidence
// from the embedded attestation, bound to the CDS cert key + the issuance
// challenge. The challenge is fixed at issuance time, so this is NOT a freshness
// proof (fresh=false) — but it ships the VCEK, so it verifies offline.
func gatherFromDiscovery(ctx context.Context, base, path, serverName string, timeout time.Duration, trust leafTrust) (*evidence, error) {
	data, src, err := fetchDiscoveryDoc(ctx, base, path, serverName, timeout)
	if err != nil {
		return nil, err
	}
	// No keyProven here, deliberately: fetchDiscoveryDoc dials with
	// InsecureSkipVerify and no VerifyPeerCertificate, so nothing binds the
	// certificate INSIDE the document to the leaf that served it. The document
	// is unauthenticated public bytes — anyone who once fetched a genuine one
	// can replay it with the certificate re-minted. See authorizeLeafBody.
	return evidenceFromDiscovery(data, src, trust)
}

// fetchDiscoveryDoc GETs the discovery document from a component's
// (unauthenticated) discovery endpoint and returns the raw bytes plus a
// human-readable source string. PKI is intentionally not verified — the trust
// anchor is the hardware attestation inside the document, checked downstream.
func fetchDiscoveryDoc(ctx context.Context, base, path, serverName string, timeout time.Duration) ([]byte, string, error) {
	if path == "" {
		path = defaultDiscoveryPath
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, "", fmt.Errorf("parse url %q: %w", base, err)
	}
	u.Path = path
	u.RawQuery = ""

	client := insecureClient(serverName, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", &connectError{err: fmt.Errorf("GET %s: %w", u.String(), err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", &connectError{err: fmt.Errorf("GET %s returned %d: %s", u.String(), resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", &connectError{err: fmt.Errorf("read discovery: %w", err)}
	}
	return data, fmt.Sprintf("discovery document %s", u.String()), nil
}

// evidenceFromDiscovery parses a discovery document into verifiable evidence.
// REPORTDATA = SHA-384(cert pubkey ‖ challenge), matching get-cert's issuance
// binding (reportDataForCSR → ratls.ReportDataForKey). The parsed certificate
// gets the same body authentication as every other cert-sourced path, and is
// retained as the evidence leaf so the --mesh-ca / --sandbox-id / --workload
// pins work against discovery targets too. A CDS-issued (CA-vouched) cert in
// the document is authenticated only by a --mesh-ca chain check; without one
// the document is rejected rather than verified against a body nothing signed
// for (authorizeLeafBody).
//
// public_tls.mode travels with the evidence to the verdict: a "webpki" front
// door terminates public TLS on a certificate this evidence says nothing
// about, so the verdict is demoted to partial downstream
// (applyFrontDoorPolicy). An unknown mode fails closed here — a
// securityError, so auto mode cannot fall through to the serving cert past a
// document it cannot classify.
func evidenceFromDiscovery(data []byte, source string, trust leafTrust) (*evidence, error) {
	var d types.DiscoveryDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	switch d.PublicTLS.Mode {
	case "", "cds", "webpki":
	default:
		return nil, &securityError{err: fmt.Errorf(
			"unknown public_tls.mode %q in discovery document (this build knows cds and webpki): the front door's serving-key binding cannot be established", d.PublicTLS.Mode)}
	}
	cert, rd, err := ratls.AttestedCertFromDiscovery(&d)
	if err != nil {
		return nil, err
	}
	body, err := authenticateLeafBody(cert)
	if err != nil {
		return nil, err
	}
	chainVerified, err := authorizeLeafBody(cert, body, trust)
	if err != nil {
		return nil, err
	}
	sandboxID, sandboxErr := ratls.SandboxIDFromCert(cert)
	workload, workloadErr := ratls.MatchedWorkloadFromCert(cert)
	sum := sha256.Sum256(cert.Raw)
	return &evidence{
		platform:          platformOrDefault(d.Attestation.Platform),
		rawEvidence:       d.Attestation.Evidence,
		erd:               keyAnchor(rd),
		fresh:             false,
		source:            source,
		certSHA256:        hex.EncodeToString(sum[:]),
		bindingNote:       "REPORTDATA binds the CDS cert key + issuance challenge from the discovery doc (ships the VCEK; no per-request nonce — replayable within the authenticated certificate validity window)",
		leaf:              cert,
		leafBody:          body,
		leafChainVerified: chainVerified,
		publicTLSMode:     d.PublicTLS.Mode,
		sandboxID:         sandboxID,
		sandboxErr:        sandboxErr,
		workload:          workload,
		workloadErr:       workloadErr,
	}, nil
}
