// Package join implements the attested rke2 node-join exchange: `c8s
// join-release` serves the cluster join token over RA-TLS on a server node,
// and `c8s join` fetches it on an agent node before rke2-agent starts.
//
// Both directions verify the peer's TDX quote via the LOCAL attestation-api
// (the in-guest idiom: the verifier is inside the caller's own TCB) and
// enforce a same-image policy: the peer's MRTD (claims.launch_digest) and
// RTMR[1], RTMR[2] must equal the verifier's own boot registers. RTMR[3] is
// excluded because it is asymmetric by design (operator boots extend the
// operator key into it, agent boots leave it empty); RTMR[0] is excluded
// because it varies with launch shape, the same reason it is absent from the
// image's published reference values.
//
// The quote is channel-bound: report_data covers the TLS leaf's public key
// (ratls.ReportDataForKey), so evidence lifted from another live CVM cannot
// be replayed by a client that does not hold the leaf key inside a TEE.
// Freshness comes from TLS 1.3 proof of possession of that key, not from
// wall-clock nonces, and is bounded by the leaf's validity window.
package join

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ErrPolicyMismatch: the peer's quote verified but its measurements are not
// this image's. Matchable via errors.Is.
var ErrPolicyMismatch = errors.New("join: peer measurement does not match this image")

// measurementHexLen is the hex length of a SHA-384 register (MRTD, RTMRs).
const measurementHexLen = 96

// certSkew tolerates clock drift when checking a peer leaf's validity window.
// That window is all that bounds replay of a stolen leaf key: neither
// direction validates the leaf through PKI (InsecureSkipVerify on the client,
// RequireAnyClientCert on the server) and the quote carries no nonce. RA-TLS
// certs are issued with NotBefore = now, so no backdating cushions it.
// CLOCK ASSUMPTION: the guest's own clock, host-influenced in a CVM.
const certSkew = 5 * time.Minute

// imageRefs are the registers the same-image policy compares. All values are
// public measurements, safe to log.
type imageRefs struct {
	// launchDigest is the MRTD (claims.launch_digest), decoded.
	launchDigest []byte
	// rtmr1/rtmr2 are lowercase hex as the attestation-api reports them.
	rtmr1 string
	rtmr2 string
}

// tdxPlatformData is the subset of the attestation-api's TDX
// claims.platform_data the policy reads.
type tdxPlatformData struct {
	Rtmr1 string `json:"rtmr_1"`
	Rtmr2 string `json:"rtmr_2"`
}

// ownRefs fetches and verifies this guest's own evidence through the local
// attestation-api and returns the registers peers must match. Verifying our
// own quote (rather than trusting an unauthenticated claims read) keeps both
// sides of the comparison in the same claims namespace and fails closed if
// the local attestation stack is broken. The values are boot-constant facts,
// so callers hold them for the process lifetime; peer verification itself
// runs per request.
func ownRefs(ctx context.Context, api attestationclient.Client) (imageRefs, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return imageRefs{}, fmt.Errorf("join: generate nonce: %w", err)
	}

	attResp, err := api.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(nonce),
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		return imageRefs{}, fmt.Errorf("join: attest own evidence: %w", err)
	}
	// The RTMR policy is native-TDX-only; any other platform has different
	// register semantics and must not be mapped onto it.
	if attResp.Platform != string(types.PlatformTdx) {
		return imageRefs{}, fmt.Errorf("join: platform %q not supported (native tdx only)", attResp.Platform)
	}

	var expected [64]byte
	copy(expected[:], nonce)
	resp, err := api.VerifyEvidence(ctx,
		types.AttestationEvidence(attResp),
		attestationclient.EvidencePolicy{ExpectedReportData: expected},
	)
	if err != nil {
		return imageRefs{}, fmt.Errorf("join: verify own evidence: %w", err)
	}
	refs, err := refsFromClaims(resp.Result.Claims)
	if err != nil {
		return imageRefs{}, fmt.Errorf("join: own claims: %w", err)
	}
	return refs, nil
}

// refsFromClaims extracts and validates the policy registers from a /verify
// response's claims.
func refsFromClaims(claims types.Claims) (imageRefs, error) {
	digest, err := hex.DecodeString(claims.LaunchDigest)
	if err != nil || len(digest) != measurementHexLen/2 {
		return imageRefs{}, fmt.Errorf("join: launch digest malformed (%d hex chars)", len(claims.LaunchDigest))
	}

	var pd tdxPlatformData
	if err := json.Unmarshal(claims.PlatformData, &pd); err != nil {
		return imageRefs{}, fmt.Errorf("join: parse platform_data: %w", err)
	}
	for name, v := range map[string]string{"rtmr_1": pd.Rtmr1, "rtmr_2": pd.Rtmr2} {
		if b, err := hex.DecodeString(v); err != nil || len(b) != measurementHexLen/2 {
			return imageRefs{}, fmt.Errorf("join: claim %s malformed (%d hex chars)", name, len(v))
		}
	}

	return imageRefs{
		launchDigest: digest,
		rtmr1:        strings.ToLower(pd.Rtmr1),
		rtmr2:        strings.ToLower(pd.Rtmr2),
	}, nil
}

// verifyPeer runs the full same-image check on a peer's RA-TLS leaf cert:
// require the leaf to be inside its validity window, extract the embedded TDX
// evidence, require it to bind the leaf's own public key (channel binding),
// verify it via the local attestation-api with the verdict enforced and MRTD
// pinned to our own, then compare RTMR[1]/RTMR[2]. This is the single
// verification path for both directions of the join exchange; nothing is
// cached between calls.
func verifyPeer(ctx context.Context, api attestationclient.Client, leaf *x509.Certificate, own imageRefs) error {
	now := time.Now()
	if now.Add(certSkew).Before(leaf.NotBefore) || now.Add(-certSkew).After(leaf.NotAfter) {
		return fmt.Errorf("join: peer cert outside its validity window (%s .. %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	att, err := ratls.ExtractAttestation(leaf)
	if err != nil {
		return fmt.Errorf("join: peer cert: %w", err)
	}
	evidence, ok := att.EmbeddedEvidence()
	if !ok {
		// TDX RA-TLS certs always embed the JSON envelope; its absence means
		// the cert is not a genuine TDX RA-TLS cert.
		return fmt.Errorf("join: peer cert carries no TDX attestation envelope")
	}
	if evidence.Platform != string(types.PlatformTdx) {
		return fmt.Errorf("join: peer platform %q not supported (native tdx only)", evidence.Platform)
	}

	rd, err := ratls.ReportDataForKey(leaf.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("join: compute expected report_data: %w", err)
	}

	// VerifyEvidence enforces the signature + report_data verdicts and the
	// MRTD allowlist (= exactly our own launch digest).
	resp, err := api.VerifyEvidence(ctx, evidence, attestationclient.EvidencePolicy{
		ExpectedReportData: rd,
		Measurements:       [][]byte{own.launchDigest},
	})
	if err != nil {
		if errors.Is(err, attestationclient.ErrMeasurementNotAllowed) {
			return fmt.Errorf("%w: launch_digest", ErrPolicyMismatch)
		}
		return fmt.Errorf("join: verify peer evidence: %w", err)
	}

	peer, err := refsFromClaims(resp.Result.Claims)
	if err != nil {
		return fmt.Errorf("join: peer claims: %w", err)
	}
	if peer.rtmr1 != own.rtmr1 {
		return fmt.Errorf("%w: rtmr_1 %s != %s", ErrPolicyMismatch, peer.rtmr1, own.rtmr1)
	}
	if peer.rtmr2 != own.rtmr2 {
		return fmt.Errorf("%w: rtmr_2 %s != %s", ErrPolicyMismatch, peer.rtmr2, own.rtmr2)
	}
	return nil
}
