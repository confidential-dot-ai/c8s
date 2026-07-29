// Package getkubeconfig implements the operator-side client (B4 client) that
// obtains a kube credential from a measured TDX CVM: it attests the node,
// confirms it booted the operator's expected guest image and was launched to
// trust the operator's key (RTMR[3]), then exchanges a CSR for a short-lived
// kube client cert over the cred-release endpoint and assembles a kubeconfig.
package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/imagemanifest"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// verifyEvidenceFn verifies a self-describing evidence envelope in-process and
// enforces the measurement policy — internal/localverify, the same path
// `c8s verify` takes, so the operator flow needs no external verifier binary
// and cannot enforce a weaker policy than the CLI. A package var so tests can
// stub the verdict.
var verifyEvidenceFn localverify.VerifyFunc = localverify.Verify

// expectedRTMR3 is the value the guest reports iff it was launched to trust
// this exact key. The operator computes it offline from their own key, so a
// match is not TOFU. The convention itself lives in pkg/runtimemeasure so the initrd,
// cred-release, and every verifier cannot drift apart.
func expectedRTMR3(operatorPubPEM []byte) string {
	reg := runtimemeasure.ForOperatorKey(operatorPubPEM)
	return hex.EncodeToString(reg[:])
}

// ImagePolicy is the guest-image pin the operator supplies out of band, from
// the confos build manifest published with the image.
//
// It is REQUIRED, and that is the point. RTMR[3] is derived from the operator's
// PUBLIC key, and the launcher — the untrusted host — is what stages that key
// on the opkeydata disk the initrd measures. So the host can boot ANY guest
// image with the operator's key staged and reproduce RTMR[3] exactly. Without
// an image pin the gate proves only "a genuine TDX guest was launched with a
// public value anyone can copy", and the node then hands back the CA and client
// cert this kubeconfig trusts. Pinning the image is what makes the verdict
// "MY cluster's software" instead.
type ImagePolicy struct {
	// ManifestPath is a confos build manifest.json; it pins MRTD, RTMR[1] and
	// RTMR[2] together so the three cannot drift apart.
	ManifestPath string
	// MeasurementHex, RTMR1Hex, RTMR2Hex are the same three values supplied
	// individually, for an operator who has the digests but not the manifest.
	MeasurementHex string
	RTMR1Hex       string
	RTMR2Hex       string
}

// WorkloadImages are the image digests the guest's runtime measurer extended
// into RTMR[3] AFTER the operator-key seed, in first-extend order.
//
// RTMR[3] is append-only and carries two kinds of value in sequence: the
// operator-key seed the initrd writes before switch_root, then one extend per
// distinct workload image the guest admits (pkg/runtimemeasure). Comparing
// against the bare seed is therefore only correct until the first workload is
// measured; after that the node reports FromDigestsSeeded(seed, digests) and a
// seed-equality check fails a perfectly healthy cluster — pushing the operator
// to drop the pin, which is the outcome the pin exists to prevent. Naming the
// expected images keeps it exact instead.
//
// Empty means "nothing measured yet": the bare seed, which is what a node
// reports before its measurer runs and always on a guest that has none.
type WorkloadImages []string

// pins is a resolved measurement policy: the launch digest allowlist plus the
// runtime registers, ready for localverify.
type pins struct {
	measurements [][]byte
	rtmrs        [4][]byte
}

// resolve turns the operator's flags into a policy, refusing anything that
// would leave the guest image unpinned.
//
// On TDX, MRTD covers the TDVF firmware's measured regions and nothing else —
// the kernel is RTMR[1] and the rootfs RTMR[2] — so a partial pin is refused
// rather than accepted as "better than nothing": it would report the same
// verdict shape as a full pin while leaving the guest OS unconstrained.
//
// workloads are the image digests the guest's runtime measurer has chained
// onto the operator-key seed in RTMR[3]; empty means the register still holds
// the bare seed.
func (p ImagePolicy) resolve(operatorPubPEM []byte, workloads WorkloadImages) (pins, error) {
	var out pins
	individual := p.MeasurementHex != "" || p.RTMR1Hex != "" || p.RTMR2Hex != ""

	switch {
	case p.ManifestPath != "" && individual:
		return out, fmt.Errorf("--image-manifest already pins MRTD, RTMR[1] and RTMR[2]; drop --measurement/--expected-rtmr1/--expected-rtmr2")

	case p.ManifestPath != "":
		image, err := imagemanifest.Load("--image-manifest", p.ManifestPath)
		if err != nil {
			return out, err
		}
		out.measurements = [][]byte{image.MRTD}
		out.rtmrs[1], out.rtmrs[2] = image.RTMR1, image.RTMR2

	case p.MeasurementHex != "" && p.RTMR1Hex != "" && p.RTMR2Hex != "":
		mrtd, err := imagemanifest.ParseRegister("--measurement", p.MeasurementHex)
		if err != nil {
			return out, err
		}
		out.measurements = [][]byte{mrtd}
		if out.rtmrs[1], err = imagemanifest.ParseRegister("--expected-rtmr1", p.RTMR1Hex); err != nil {
			return out, err
		}
		if out.rtmrs[2], err = imagemanifest.ParseRegister("--expected-rtmr2", p.RTMR2Hex); err != nil {
			return out, err
		}

	case individual:
		return out, fmt.Errorf("an incomplete image pin proves less than it appears to: MRTD covers only the TDVF firmware, the guest kernel is RTMR[1] and the rootfs RTMR[2]. Pass all of --measurement/--expected-rtmr1/--expected-rtmr2, or --image-manifest to pin the three together")

	default:
		return out, fmt.Errorf("refusing to verify without a guest-image pin: RTMR[3] is derived from your PUBLIC key and the host stages that key at launch, so any TDX guest — including one running the host's own image — can reproduce it. Pass --image-manifest (the confos manifest.json published with your image), or all of --measurement/--expected-rtmr1/--expected-rtmr2")
	}

	// RTMR[3] closes the other half: the image is the operator's, and this
	// deployment was launched to trust the operator's key. Per-workload
	// extends chain onto that seed in first-extend order, so the expected
	// register is the seed only while nothing has been measured yet.
	reg, err := workloads.expectedRTMR3(operatorPubPEM)
	if err != nil {
		return pins{}, err
	}
	out.rtmrs[3] = reg
	return out, nil
}

// expectedRTMR3 computes the register value a node reports for this operator
// key after measuring w, in order. Digests are canonicalized and deduplicated
// first-seen, mirroring the in-guest measurer: it extends each DISTINCT image
// once, so restarts and replicas do not double-extend the append-only
// register. A reference that is not digest-pinned is refused — a tag is not
// content-bound, so it cannot name what was measured.
func (w WorkloadImages) expectedRTMR3(operatorPubPEM []byte) ([]byte, error) {
	seed := runtimemeasure.ForOperatorKey(operatorPubPEM)
	seen := make(map[string]bool, len(w))
	digests := make([]string, 0, len(w))
	for _, ref := range w {
		d, err := runtimemeasure.CanonicalDigest(ref)
		if err != nil {
			return nil, fmt.Errorf("--workload-image %q: %w", ref, err)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		digests = append(digests, d)
	}
	reg := runtimemeasure.FromDigestsSeeded(seed, digests)
	return reg[:], nil
}

// verifyEvidence verifies an evidence envelope in-process (HW chain +
// report_data binding) and enforces the full measurement policy: the launch
// digest allowlist, the guest image registers, and the operator-key binding in
// RTMR[3]. expectedReportData is what the quote must be bound to: the caller's
// nonce on the attest gate, the cert-key hash on the RA-TLS dial. Fails closed
// on any missing piece.
func verifyEvidence(ctx context.Context, envelopeJSON, expectedReportData []byte, policy pins) (*teetypes.VerificationResult, error) {
	// The operator-key binding lives in RTMR[3], which only TDX measures, so
	// reject other platforms up front with a clear error instead of a late
	// "quote carries no rtmr_3" (e.g. a SEV-SNP node can never satisfy the
	// binding, however genuine its quote).
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse evidence envelope: %w", err)
	}
	if env.Platform != teetypes.PlatformTDX {
		return nil, fmt.Errorf("node platform is %q: the operator-key binding lives in RTMR[3], so credential release requires a TDX guest", env.Platform)
	}

	res, err := verifyEvidenceFn(ctx, string(teetypes.PlatformTDX), envelopeJSON, localverify.Params{
		ExpectedReportData: expectedReportData,
		Measurements:       policy.measurements,
		ExpectedRTMRs:      policy.rtmrs,
	})
	if err != nil {
		return nil, fmt.Errorf("verify evidence: %w", err)
	}
	// Defense in depth: a nil error already implies these, but never report a
	// success the result contradicts.
	if !res.SignatureValid {
		return nil, fmt.Errorf("quote signature invalid")
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return nil, fmt.Errorf("report_data does not match the expected binding (stale/replayed quote)")
	}
	return res, nil
}

// attestAndCheck fetches a nonce-bound quote from the guest's attestation-api
// and verifies it in-process against the full policy. It proves: genuine TDX,
// running the operator's expected guest image, launched to trust the
// operator's key. Returns nil on success.
func attestAndCheck(ctx context.Context, attestURL string, policy pins) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	evidence, err := postAttest(ctx, attestURL, nonce)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	_, err = verifyEvidence(ctx, evidence, nonce, policy)
	return err
}

// postAttest sends the nonce to POST /attest and returns the raw evidence body
// (the self-describing {platform, evidence} envelope attestation-go consumes).
//
// report_data goes to /attest base64-encoded (what the attestation-api
// decodes); attestation-go compares the same raw bytes. Matches confai's
// verify.
func postAttest(ctx context.Context, attestURL string, nonce []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"platform":    "auto",
		"report_data": base64.StdEncoding.EncodeToString(nonce),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest HTTP %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}
