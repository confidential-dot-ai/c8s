package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// HandoffEARSource produces the cert-issuer's own EAR token that handoff
// responses sign over. Implementations must be safe for concurrent reads.
type HandoffEARSource interface {
	Current() (string, error)
}

// AtomicHandoffEAR is a HandoffEARSource backed by an atomic.Value so the
// refresher goroutine can swap the token without locking the request path.
type AtomicHandoffEAR struct {
	v atomic.Value // string
}

func (a *AtomicHandoffEAR) Current() (string, error) {
	if v, _ := a.v.Load().(string); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("handoff EAR not yet bootstrapped")
}

func (a *AtomicHandoffEAR) Set(token string) {
	a.v.Store(token)
}

// HandoffBootstrap generates the cert-issuer's handoff signer key in process,
// gets a TEE attestation report binding it via the local attestation service,
// and exchanges that for an EAR with Assam's /attest-key endpoint over RA-TLS.
//
// The result is what the handoff handler needs: an in-memory signer key plus
// a refreshing EAR source. There are no operator-supplied key files; the
// alternative would be mounting a Secret-backed PEM into the cert-issuer pod,
// which contradicts the chart-managed CVM design ("CA private material never
// passes through Kubernetes Secrets" — see docs/THREAT_MODEL.md).
type HandoffBootstrap interface {
	Signer() *ecdsa.PrivateKey
	EARSource() HandoffEARSource
	RunRefresh(ctx context.Context, logger *slog.Logger)
}

type handoffBootstrap struct {
	signer    *ecdsa.PrivateKey
	earSource *AtomicHandoffEAR

	assamClient           attestclient.Client
	attestationServiceURL string
}

var _ HandoffBootstrap = (*handoffBootstrap)(nil)

// NewHandoffBootstrap generates the handoff signer key and prepares the
// RA-TLS client to Assam. It does NOT call /attest-key — that happens in the
// RunRefresh loop, so cert-issuer can start independently of Assam's
// reachability. The /handoff endpoint stays registered but returns 503
// (via the EAR source's not-yet-ready error) until the first refresh
// succeeds.
func NewHandoffBootstrap(assamURL, attestationServiceURL string, assamMeasurements [][]byte) (HandoffBootstrap, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff signer key: %w", err)
	}
	httpClient, err := ratls.NewVerifyingHTTPClient(assamMeasurements, attestationServiceURL)
	if err != nil {
		return nil, err
	}
	return &handoffBootstrap{
		signer:                signer,
		earSource:             &AtomicHandoffEAR{},
		assamClient:           attestclient.NewClientWithHTTP(assamURL, httpClient),
		attestationServiceURL: attestationServiceURL,
	}, nil
}

func (h *handoffBootstrap) Signer() *ecdsa.PrivateKey {
	return h.signer
}

func (h *handoffBootstrap) EARSource() HandoffEARSource {
	return h.earSource
}

// RunRefresh runs the initial /attest-key call and then re-attests the
// handoff signer key on a schedule keyed off the current EAR's expiry.
// Refreshes happen at half the remaining validity so a single failed attempt
// has another chance before workloads see expired tokens.
//
// The first iteration is the initial bootstrap. Until it succeeds the EAR
// source returns "not yet bootstrapped" and HandleHandoff returns 503.
// Failures during refresh keep the previous EAR (if any) serving — the
// handler keeps working until that EAR's exp passes.
func (h *handoffBootstrap) RunRefresh(ctx context.Context, logger *slog.Logger) {
	pubDER, err := x509.MarshalPKIXPublicKey(&h.signer.PublicKey)
	if err != nil {
		logger.Error("handoff refresher: marshal pubkey", "error", err)
		return
	}

	for {
		refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, err := h.assamClient.AttestKey(refreshCtx, h.attestationServiceURL, pubDER)
		cancel()
		if err != nil {
			if _, curErr := h.earSource.Current(); curErr != nil {
				logger.Warn("handoff bootstrap: attest-key failed; will retry", "error", err)
			} else {
				logger.Warn("handoff refresh: attest-key failed; keeping previous EAR", "error", err)
			}
		} else {
			h.earSource.Set(token)
			if _, curErr := h.earSource.Current(); curErr == nil {
				logger.Info("handoff EAR refreshed")
			}
		}

		current, _ := h.earSource.Current()
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextRefreshAfter(current)):
		}
	}
}

// LocalEARMinter mints an EAR over a TEE-attested ECDSA public key. It is the
// EAR-issuance half of the attestation /attest-key flow, used by the unified
// CDS to self-provision its handoff signer EAR in process — CDS is its own EAR
// issuer, so there is no external Assam to dial (contrast NewHandoffBootstrap).
type LocalEARMinter interface {
	IssueWithLaunchDigestAndPubKey(submodsEvidence json.RawMessage, launchDigest string, teePubKey *ecdsa.PublicKey) (string, error)
}

// AttestationService is the attestation-service client the bootstrap drives:
// Attest produces a TEE report binding reportData, Verify checks the report's
// signature and report-data and returns the launch digest. *attestationclient.Client
// satisfies it, so the same client used elsewhere in CDS is reused here.
type AttestationService interface {
	Attest(ctx context.Context, req types.AttestRequest) (types.AttestResponse, error)
	Verify(ctx context.Context, req types.VerifyRequest) (types.VerifyResponse, error)
}

type localHandoffBootstrap struct {
	signer    *ecdsa.PrivateKey
	earSource *AtomicHandoffEAR

	attestation AttestationService
	minter      LocalEARMinter
}

var _ HandoffBootstrap = (*localHandoffBootstrap)(nil)

// NewLocalHandoffBootstrap generates the handoff signer key and prepares an
// in-process attest-key flow against the local attestation service. Unlike
// NewHandoffBootstrap it issues the EAR with the supplied minter (CDS's own EAR
// issuer) rather than dialing a remote Assam — there is no RA-TLS hop and no
// remote measurement to pin, because the evidence is verified and the EAR
// signed inside the CDS trust boundary.
func NewLocalHandoffBootstrap(attestation AttestationService, minter LocalEARMinter) (HandoffBootstrap, error) {
	if attestation == nil || minter == nil {
		return nil, fmt.Errorf("local handoff bootstrap requires an attestation service and EAR minter")
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff signer key: %w", err)
	}
	return &localHandoffBootstrap{
		signer:      signer,
		earSource:   &AtomicHandoffEAR{},
		attestation: attestation,
		minter:      minter,
	}, nil
}

func (h *localHandoffBootstrap) Signer() *ecdsa.PrivateKey { return h.signer }

func (h *localHandoffBootstrap) EARSource() HandoffEARSource { return h.earSource }

// RunRefresh mirrors handoffBootstrap.RunRefresh: an initial bootstrap attempt
// followed by re-attestation keyed off the current EAR's expiry. The /handoff
// endpoint returns 503 until the first attestKey succeeds.
func (h *localHandoffBootstrap) RunRefresh(ctx context.Context, logger *slog.Logger) {
	pubDER, err := x509.MarshalPKIXPublicKey(&h.signer.PublicKey)
	if err != nil {
		logger.Error("handoff refresher: marshal pubkey", "error", err)
		return
	}

	for {
		refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, err := h.attestKey(refreshCtx, pubDER)
		cancel()
		if err != nil {
			if _, curErr := h.earSource.Current(); curErr != nil {
				logger.Warn("handoff bootstrap: local attest-key failed; will retry", "error", err)
			} else {
				logger.Warn("handoff refresh: local attest-key failed; keeping previous EAR", "error", err)
			}
		} else {
			h.earSource.Set(token)
			logger.Info("handoff EAR refreshed (local)")
		}

		current, _ := h.earSource.Current()
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextRefreshAfter(current)):
		}
	}
}

// attestKey runs the /attest-key flow in process: generate evidence binding the
// signer pubkey to a report, verify the report's signature and report-data
// match, then mint the EAR over the verified launch digest.
//
// INVARIANT: the EAR is minted only after the verifier confirms SignatureValid
// and ReportDataMatch — the same gate the HTTP /attest-key handler enforces. We
// verify even though CDS produced the evidence: the verifier supplies the
// launch digest claim, and skipping verification would let a host-supplied
// evidence blob set the EAR's launch digest.
func (h *localHandoffBootstrap) attestKey(ctx context.Context, pubDER []byte) (string, error) {
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "", fmt.Errorf("parse signer pubkey: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("signer pubkey is not ECDSA")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	reportData, err := ratls.ReportDataForKey(ecPub, challenge)
	if err != nil {
		return "", err
	}

	reportDataDigest := reportData[:sha512.Size384]
	asResp, err := h.attestation.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportDataDigest),
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		return "", fmt.Errorf("generate evidence: %w", err)
	}

	verifyResp, err := h.attestation.Verify(ctx, types.VerifyReportData(
		types.AttestationEvidence(asResp),
		types.NewBase64Bytes(reportDataDigest),
	))
	if err != nil {
		return "", fmt.Errorf("verify evidence: %w", err)
	}
	if !verifyResp.Result.SignatureValid {
		return "", fmt.Errorf("attestation signature invalid")
	}
	if verifyResp.Result.ReportDataMatch == nil || !*verifyResp.Result.ReportDataMatch {
		return "", fmt.Errorf("report-data mismatch in attestation evidence")
	}

	evidenceJSON, err := json.Marshal(asResp)
	if err != nil {
		return "", fmt.Errorf("marshal evidence for EAR: %w", err)
	}
	return h.minter.IssueWithLaunchDigestAndPubKey(json.RawMessage(evidenceJSON), verifyResp.Result.Claims.LaunchDigest, ecPub)
}

// HandoffEARExpiry returns the EAR token's exp claim. The token is decoded
// without signature verification — this is for operator-facing observability
// of the locally provisioned EAR. Handoff peers re-validate signature, issuer,
// and expiry via ValidateEARToken before trusting any material.
func HandoffEARExpiry(token string) (time.Time, error) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse JWT: %w", err)
	}
	claims, err := jwt.Parse(msg.Payload(), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse JWT claims: %w", err)
	}
	exp := claims.Expiration()
	if exp.IsZero() || exp.Unix() == 0 {
		return time.Time{}, fmt.Errorf("JWT missing exp claim")
	}
	return exp, nil
}

// nextRefreshAfter returns the duration until the next refresh attempt for
// the supplied token. Half the remaining validity, clamped to a sane band so
// we don't hammer Assam on every tick when the token is brand new and don't
// sleep forever on a malformed token.
func nextRefreshAfter(token string) time.Duration {
	const (
		minRefresh = 30 * time.Second
		maxRefresh = 1 * time.Hour
	)
	if token == "" {
		return minRefresh
	}
	exp, err := HandoffEARExpiry(token)
	if err != nil {
		return minRefresh
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		return minRefresh
	}
	d := remaining / 2
	if d < minRefresh {
		return minRefresh
	}
	if d > maxRefresh {
		return maxRefresh
	}
	return d
}
