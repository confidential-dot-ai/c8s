// Package snpvcek inlines the AMD VCEK certificate into bare SEV-SNP
// attestation evidence that lacks cert_chain.vcek, so offline verifiers
// (c8s-verify-js) can check the chain without network. The VCEK is public
// per-chip collateral: attestation-go derives its AMD KDS URL from the report
// and verifies report + chain against the bundled AMD roots before the fetched
// certificate is embedded or cached, so an embedded certificate can only fail
// a client's verification, never forge it.
//
// Delete this package once attestation-api embeds the chain itself at /attest.
package snpvcek

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// One bounded fetch per Embed; after a KDS failure no call retries until the
// backoff has passed (the sidecar calls Embed per unauthenticated request).
const (
	kdsTimeout     = 5 * time.Second
	failureBackoff = 30 * time.Second
)

// Embedder fetches the process's VCEK and embeds it into evidence. One entry
// is cached, keyed by its KDS URL (chip and TCB): a process attests one chip,
// and the URL changes only on a firmware update. Safe for concurrent use; the
// zero value is not usable, call New.
type Embedder struct {
	fetch trust.HTTPSGetter

	mu          sync.Mutex
	cachedURL   string
	cachedDER   []byte
	lastFailure time.Time
}

// New returns an Embedder that fetches from AMD KDS.
func New() *Embedder {
	return NewWithGetter(&trust.SimpleHTTPSGetter{})
}

// NewWithGetter is New with a caller-supplied collateral getter (tests).
func NewWithGetter(getter trust.HTTPSGetter) *Embedder {
	return &Embedder{fetch: getter}
}

// Embed returns evidence with cert_chain.vcek inlined. Evidence for a platform
// other than "snp", or already carrying a VCEK, passes through unchanged. On
// any failure it returns the original evidence and the error: callers log and
// ship the evidence chainless, which online verifiers handle by fetching the
// VCEK themselves.
func (e *Embedder) Embed(ctx context.Context, platform string, evidence json.RawMessage) (json.RawMessage, error) {
	if platform != "snp" {
		return evidence, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(evidence, &fields); err != nil {
		return evidence, fmt.Errorf("parse snp evidence: %w", err)
	}
	if hasVCEK(fields["cert_chain"]) {
		return evidence, nil
	}
	var reportB64 string
	if err := json.Unmarshal(fields["attestation_report"], &reportB64); err != nil {
		return evidence, fmt.Errorf("parse attestation_report: %w", err)
	}
	reportBytes, err := base64.StdEncoding.DecodeString(reportB64)
	if err != nil {
		return evidence, fmt.Errorf("decode attestation_report: %w", err)
	}

	vcekDER, err := e.vcek(ctx, reportBytes)
	if err != nil {
		return evidence, err
	}

	chain, err := json.Marshal(snp.SnpCertChain{Vcek: base64.StdEncoding.EncodeToString(vcekDER)})
	if err != nil {
		return evidence, err
	}
	fields["cert_chain"] = chain
	enriched, err := json.Marshal(fields)
	if err != nil {
		return evidence, err
	}
	return enriched, nil
}

// hasVCEK reports whether a raw cert_chain value already carries a VCEK.
func hasVCEK(certChain json.RawMessage) bool {
	var chain snp.SnpCertChain
	return json.Unmarshal(certChain, &chain) == nil && chain.Vcek != ""
}

// vcek returns the report's VCEK DER, from the cache or AMD KDS. The report is
// verified by attestation-go — the engine behind `c8s verify`, which derives
// the KDS URL from the report itself (Zen4c-aware) and fetches through a
// capturing getter — before a fetched certificate is returned or cached, so
// one bad KDS response can never poison the cache.
func (e *Embedder) vcek(ctx context.Context, reportBytes []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// The fetch outlives the caller's cancellation: an aborted client request
	// must not record a KDS failure (arming the backoff) or waste the fetch.
	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), kdsTimeout)
	defer cancel()

	capture := &capturingGetter{e: e, ctx: verifyCtx}
	_, err := snp.VerifyReportContext(verifyCtx, reportBytes, nil, teetypes.VerifyParams{},
		teetypes.PlatformSNP, snp.MinReportVersion, snp.Options{Getter: capture})
	if err != nil {
		// Arm the backoff only when KDS was actually tried: a fetch that
		// failed, or a fetched body the verification rejected.
		if capture.attempted {
			e.lastFailure = time.Now()
		}
		return nil, fmt.Errorf("evidence did not verify against AMD collateral: %w", err)
	}
	if capture.url != "" {
		e.cachedURL, e.cachedDER = capture.url, capture.body
	}
	if len(e.cachedDER) == 0 {
		return nil, fmt.Errorf("verification succeeded without a VCEK; refusing to embed")
	}
	return e.cachedDER, nil
}

// capturingGetter serves the Embedder's cached VCEK for its URL, fetches
// anything else through the inner getter (honoring the failure backoff), and
// records the fetch for the Embedder to cache once verification succeeds.
type capturingGetter struct {
	e         *Embedder
	ctx       context.Context
	attempted bool
	url       string
	body      []byte
}

func (g *capturingGetter) Get(url string) ([]byte, error) {
	if url == g.e.cachedURL {
		return g.e.cachedDER, nil
	}
	if since := time.Since(g.e.lastFailure); since < failureBackoff {
		return nil, fmt.Errorf("AMD KDS fetch failed %s ago; backing off", since.Round(time.Second))
	}
	g.attempted = true
	body, err := trust.GetWith(g.ctx, g.e.fetch, url)
	if err != nil {
		return nil, err
	}
	g.url, g.body = url, body
	return body, nil
}
