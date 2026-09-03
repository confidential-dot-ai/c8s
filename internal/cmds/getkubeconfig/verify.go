// Package getkubeconfig implements the operator-side client (B4 client) that
// obtains a kube credential from a measured CVM: it attests the node,
// confirms the full measured identity — on TDX the image tuple (MRTD,
// RTMR[1], RTMR[2]) plus the RTMR[3] chain seeded by the operator's key,
// extended by the dynamic mode event and then by the expected workload
// images; on SEV-SNP the pinned per-SMP
// launch digest plus the operator-key HOSTDATA binding — then exchanges a CSR
// for a short-lived kube client cert over the cred-release endpoint and
// assembles a kubeconfig.
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
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// verifyEnvelope verifies a self-describing evidence envelope in-process with
// attestation-go, the same engine `c8s verify` uses, so the operator flow
// needs no external verifier binary. A package var so tests can stub the
// verdict.
var verifyEnvelope = teeverify.Verify

// measuredPolicy is the full trust gate a node must satisfy before any
// credential flows: the TDX image tuple from one provenanced build-artifact
// manifest, and the expected RTMR[3] chain. RTMR[3] alone is not an identity
// gate — the untrusted host stages the operator key, so it can boot ANY image
// and reproduce the operator-key/mode register — which is why the image tuple
// anchors the policy and RTMR[3] then binds the key and workload set.
type measuredPolicy struct {
	// platform is the TEE this policy gates, inferred from the manifest's
	// shape (see policyFor). Other platforms are refused before the claims
	// are read.
	platform teetypes.PlatformType

	pins runtimemeasure.ImagePins
	// rtmr3 is the expected runtime register, TDX only. On an operator-key
	// boot: FromDigestsSeeded(ForDynamic(ForOperatorKey(pubPEM)), workload
	// digests) — the operator-key seed, the dynamic mode event the node image
	// extends before containerd, then the workload extends (ForDynamic(seed)
	// alone when no workload images are expected). On a static boot:
	// ForStaticAllowlist(bundle index).
	rtmr3 [runtimemeasure.Size]byte
	// chainMeaning names, for diagnostics, what binds the operator to the
	// node beyond the image tuple: the RTMR[3] chain on TDX, the HOSTDATA
	// binding on SEV-SNP.
	chainMeaning string

	// SNP: the pinned per-SMP launch digests plus the operator-key binding
	// committed as HOSTDATA at launch. No runtime-extend register, so there
	// is no workload chain to pin (c8s#331).
	snpPins  runtimemeasure.SNPImagePins
	hostData [runtimemeasure.HostDataSize]byte
}

// policyFor builds the trust gate from the operator's inputs: the image
// manifest (MRTD + RTMR[1] + RTMR[2], loaded atomically), the operator public
// key PEM (the exact bytes the initrd hashed), and the ordered digest-pinned
// workload images the node's measurer is expected to have extended, in
// first-extend order. Tag references are rejected — only a canonical digest
// identifies an image.
func policyFor(manifestPath string, operatorPubPEM []byte, workloadImages []string) (measuredPolicy, error) {
	// The manifest's shape names the platform: a TDX build publishes the
	// mrtd/rtmr1/rtmr2 tuple, an SNP build publishes snp_variants (per-SMP
	// launch digests). TDX is tried first so a manifest that is neither keeps
	// the TDX error text.
	pins, tdxErr := runtimemeasure.LoadImageManifest(manifestPath)
	if tdxErr == nil {
		return tdxPolicy(pins, operatorPubPEM, workloadImages)
	}
	snpPins, snpErr := runtimemeasure.LoadSNPImageManifest(manifestPath)
	if snpErr != nil {
		return measuredPolicy{}, fmt.Errorf("--image-manifest: %w", tdxErr)
	}
	return snpPolicy(snpPins, operatorPubPEM, workloadImages)
}

// snpPolicy pins the per-SMP launch-digest set and the HOSTDATA operator-key
// binding. SNP has no runtime-extend register, so there is no workload chain.
func snpPolicy(pins runtimemeasure.SNPImagePins, operatorPubPEM []byte, workloadImages []string) (measuredPolicy, error) {
	// Accepting --workload-image here would claim an enforcement that cannot
	// exist rather than silently ignoring the flag.
	if len(workloadImages) > 0 {
		return measuredPolicy{}, fmt.Errorf("--workload-image requires a TDX node: SEV-SNP has no runtime measurement register, so workload extends cannot be verified; rerun without it")
	}
	return measuredPolicy{
		platform:     teetypes.PlatformSNP,
		snpPins:      pins,
		hostData:     runtimemeasure.HostDataForOperatorKey(operatorPubPEM),
		chainMeaning: "operator-key HOSTDATA binding",
	}, nil
}

// tdxPolicy pins the image tuple and the RTMR[3] chain: the operator-key seed,
// the dynamic mode event, then each digest-pinned workload image in
// first-extend order.
func tdxPolicy(pins runtimemeasure.ImagePins, operatorPubPEM []byte, workloadImages []string) (measuredPolicy, error) {
	digests := make([]string, 0, len(workloadImages))
	seen := make(map[string]string, len(workloadImages))
	for _, ref := range workloadImages {
		d, err := runtimemeasure.CanonicalDigest(ref)
		if err != nil {
			return measuredPolicy{}, fmt.Errorf("--workload-image: %w", err)
		}
		// RTMR[3] is an ordered extend chain over the deduped digest set (see
		// FromDigests): the node's measurer extends a given image once, so a
		// repeated ref here extends the expected register one time too many
		// and produces a gate NO node can ever satisfy. Reject it rather than
		// dedup silently — a repeat is a copy/paste, and a permanently red
		// gate is worse than a usage error.
		if prev, dup := seen[d]; dup {
			return measuredPolicy{}, fmt.Errorf("--workload-image %q and %q are the same image (%s): each expected image must be given once, in first-extend order, or the expected RTMR[3] chain can never match the node's", prev, ref, d)
		}
		seen[d] = ref
		digests = append(digests, d)
	}
	return measuredPolicy{
		platform:     teetypes.PlatformTDX,
		pins:         pins,
		rtmr3:        runtimemeasure.FromDigestsSeeded(runtimemeasure.ForDynamic(runtimemeasure.ForOperatorKey(operatorPubPEM)), digests),
		chainMeaning: "operator-key + dynamic mode event + workload chain",
	}, nil
}

// verifyEvidence verifies an evidence envelope with attestation-go (HW chain +
// report_data binding) and enforces the full measured-identity policy on the
// verified claims. expectedReportData is what the quote must be bound to: the
// caller's nonce on the attest gate, the cert-key hash on the RA-TLS dial.
// Both paths funnel through here so the two gates cannot diverge. Fails
// closed on any missing piece.
func verifyEvidence(envelopeJSON, expectedReportData []byte, exp measuredPolicy) (*teetypes.VerificationResult, error) {
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse evidence envelope: %w", err)
	}
	// The policy's platform comes from the manifest; the node must be that
	// platform. Bare-metal snp only: on az-snp/gcp-snp the HOSTDATA field is
	// owned by the cloud stack, so it cannot carry the operator-key binding.
	if env.Platform != exp.platform {
		return nil, fmt.Errorf("node platform is %q but --image-manifest pins %q: credential release requires the node to be the platform the manifest describes", env.Platform, exp.platform)
	}
	if len(env.Evidence) == 0 {
		return nil, fmt.Errorf("evidence envelope carries no evidence object")
	}
	// The envelope is single-wrap: {platform, evidence:<platform object>}. A
	// double-wrapped envelope would reach the verifier as evidence whose
	// fields it ignores or misparses — refuse it loudly instead.
	var inner struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if json.Unmarshal(env.Evidence, &inner) == nil && inner.Platform != "" && len(inner.Evidence) > 0 {
		return nil, fmt.Errorf("evidence envelope is double-wrapped ({platform,evidence} inside evidence); the envelope must wrap the platform evidence object exactly once")
	}

	// Bare-metal SNP evidence is a raw report with NO inline VCEK — the guest
	// attestation-api serves cert_chain: null and offers no endpoint to fetch
	// one — so attestation-go's offline path cannot verify it. localverify
	// handles that shape and fetches the VCEK from AMD KDS, and is already
	// what the RA-TLS dial arm uses; routing the gate through it too keeps
	// the two halves of one policy able to consume the same evidence (c8s#415).
	if exp.platform == teetypes.PlatformSNP {
		return verifySNPEvidence(env, expectedReportData, exp)
	}

	res, err := verifyEnvelope(envelopeJSON, teetypes.VerifyParams{
		ExpectedReportData: expectedReportData,
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
	if err := checkMeasuredIdentity(res, exp); err != nil {
		return nil, err
	}
	return res, nil
}

// checkMeasuredIdentity asserts the verified claims match the full policy:
// MRTD against the launch digest, RTMR[1]/[2] against the image tuple,
// RTMR[3] against the operator-key/mode/workload chain. The compares are over the
// claims attestation-go extracted from the signature-verified quote body.
// Absent or malformed claims fail closed.
func checkMeasuredIdentity(res *teetypes.VerificationResult, exp measuredPolicy) error {
	if exp.platform == teetypes.PlatformSNP {
		return checkSNPMeasuredIdentity(res, exp)
	}
	launch := strings.ToLower(strings.TrimSpace(res.Claims.LaunchDigest))
	if launch == "" {
		return fmt.Errorf("verified claims carry no launch digest (MRTD)")
	}
	if want := hex.EncodeToString(exp.pins.MRTD[:]); launch != want {
		return fmt.Errorf("MRTD mismatch: node reports %s, image manifest pins %s (a different guest firmware/image booted)", launch, want)
	}
	for _, reg := range []struct {
		idx     int
		meaning string
		want    [runtimemeasure.Size]byte
	}{
		{1, "guest kernel", exp.pins.RTMR1},
		{2, "guest rootfs", exp.pins.RTMR2},
		{3, exp.chainMeaning, exp.rtmr3},
	} {
		got, err := res.Claims.RTMR(reg.idx)
		if err != nil {
			return fmt.Errorf("RTMR[%d] mismatch (%s): %w", reg.idx, reg.meaning, err)
		}
		if !bytes.Equal(got, reg.want[:]) {
			return fmt.Errorf("RTMR[%d] mismatch (%s): node reports %x, expected %x", reg.idx, reg.meaning, got, reg.want)
		}
	}
	return nil
}

// checkSNPMeasuredIdentity asserts the verified claims match the SNP policy:
// the launch digest against the pinned per-SMP set, and HOSTDATA against the
// operator-key binding the launcher committed. Together these are the SNP
// analog of TDX's image tuple + RTMR[3] (c8s#331). Absent or malformed claims
// fail closed.
func checkSNPMeasuredIdentity(res *teetypes.VerificationResult, exp measuredPolicy) error {
	launch := strings.ToLower(strings.TrimSpace(res.Claims.LaunchDigest))
	if launch == "" {
		return fmt.Errorf("verified claims carry no launch digest (SNP MEASUREMENT)")
	}
	var got [runtimemeasure.Size]byte
	raw, err := hex.DecodeString(launch)
	if err != nil || len(raw) != runtimemeasure.Size {
		return fmt.Errorf("launch digest %q is not %d hex chars", launch, runtimemeasure.Size*2)
	}
	copy(got[:], raw)
	if !exp.snpPins.Has(got) {
		return fmt.Errorf("launch digest mismatch: node reports %s, image manifest pins %s (a different guest image booted, or a vCPU count the manifest has no variant for)",
			launch, exp.snpPins)
	}

	// HOSTDATA carries the operator-key binding. A VM launched without
	// --operator-key reports all-zero, which no SHA-256 output equals, so a
	// stripped binding fails here.
	hostData := []byte(res.Claims.InitData)
	if len(hostData) == 0 {
		return fmt.Errorf("quote carries no HOSTDATA (the operator-key binding)")
	}
	// Width matters: a TDX MRCONFIGID is 48 bytes and must never be compared
	// against a 32-byte SNP binding by truncation.
	if len(hostData) != runtimemeasure.HostDataSize {
		return fmt.Errorf("HOSTDATA is %d bytes, want %d", len(hostData), runtimemeasure.HostDataSize)
	}
	if !bytes.Equal(hostData, exp.hostData[:]) {
		return fmt.Errorf("HOSTDATA mismatch: node reports %s, operator key implies %s (the VM was not launched for this key)",
			hex.EncodeToString(hostData), hex.EncodeToString(exp.hostData[:]))
	}
	return nil
}

// attestAndVerify fetches a nonce-bound quote from the guest's
// attestation-api, verifies it in-process (HW chain + report_data freshness),
// and enforces the full measured-identity policy. It proves: genuine TDX +
// the pinned guest image booted + the node trusts the operator's key and ran
// exactly the expected workload extends. Returns nil on success.
func attestAndVerify(ctx context.Context, attestURL string, exp measuredPolicy) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	evidence, err := postAttest(ctx, attestURL, nonce)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	_, err = verifyEvidence(evidence, nonce, exp)
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

// snpAttestTimeout bounds the gate's verification, whose collateral fetch
// (VCEK from AMD KDS) crosses the network.
const snpAttestTimeout = 30 * time.Second

// verifySNPEvidence is verifyEvidence's SNP arm. It verifies a bare-metal SNP
// envelope through localverify — which accepts the raw-report shape and pulls
// the VCEK from AMD KDS, rather than requiring the guest to have volunteered
// it inline — then enforces the same measured identity the RA-TLS dial does.
//
// The engine already enforces both pins (Measurements, ExpectedInitDataHash);
// checkSNPMeasuredIdentity re-checks them over the returned claims so a
// success the claims contradict is never accepted.
func verifySNPEvidence(env teetypes.AttestationEvidence, expectedReportData []byte, exp measuredPolicy) (*teetypes.VerificationResult, error) {
	measurements := make([][]byte, 0, len(exp.snpPins.BySMP))
	for _, d := range exp.snpPins.Digests() {
		measurements = append(measurements, append([]byte(nil), d[:]...))
	}

	ctx, cancel := context.WithTimeout(context.Background(), snpAttestTimeout)
	defer cancel()
	res, err := verifySNPRATLS(ctx, string(env.Platform), env.Evidence, localverify.Params{
		ExpectedReportData:   expectedReportData,
		Measurements:         measurements,
		ExpectedInitDataHash: exp.hostData[:],
	})
	if err != nil {
		return nil, fmt.Errorf("verify evidence: %w", err)
	}
	if !res.SignatureValid {
		return nil, fmt.Errorf("quote signature invalid")
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return nil, fmt.Errorf("report_data does not match the expected binding (stale/replayed quote)")
	}
	if err := checkSNPMeasuredIdentity(res, exp); err != nil {
		return nil, err
	}
	return res, nil
}

// attestedSummary is the one-line account of what the gate proved, for the
// final status line.
func (p measuredPolicy) attestedSummary() string {
	return "image tuple + " + p.chainMeaning + " verified"
}
