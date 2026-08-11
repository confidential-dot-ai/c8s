package join

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// nodePolicyFileVersion is deliberately explicit. A join token admits a node
// to the cluster, so accepting a policy shape we do not understand would be a
// security bug, not a compatibility feature.
const nodePolicyFileVersion = 1

// nodePolicyFile is the on-disk, versioned input for heterogeneous node join.
// It is JSON rather than flags because each platform needs its own measurement
// and security policy. The file is public policy data, not a credential.
type nodePolicyFile struct {
	Version   int                  `json:"version"`
	Platforms []nodePlatformPolicy `json:"platforms"`
}

// nodePlatformPolicy is the policy for one native node TEE. Only native SNP
// and native TDX are accepted in version 1. Cloud/vTPM forms need separate
// node-image and lifecycle work and must not be admitted by accident.
type nodePlatformPolicy struct {
	Platform     string   `json:"platform"`
	Measurements []string `json:"measurements"`
	// AllowPeers is the set of registered node platforms this platform may
	// admit during the join exchange. It is explicit because registration is
	// not the same thing as authorization to join this cluster.
	AllowPeers []string      `json:"allow_peers"`
	MinTCB     *types.MinTcb `json:"min_tcb,omitempty"`
	TDX        *tdxPolicy    `json:"tdx,omitempty"`
}

// tdxPolicy pins complete RTMR[1]/RTMR[2] pairs. A pair is intentional: two
// independent allowlists would admit combinations never approved together.
// Omit tdx to pin MRTD only. This is not the legacy same-image mode.
type tdxPolicy struct {
	Profiles []tdxProfile `json:"profiles"`
}

type tdxProfile struct {
	RTMR1 string `json:"rtmr_1"`
	RTMR2 string `json:"rtmr_2"`
}

type nodePolicyRegistry struct {
	byPlatform map[string]compiledNodePolicy
}

type compiledNodePolicy struct {
	platform     string
	measurements [][]byte
	minTCB       *types.MinTcb
	tdxProfiles  map[string]bool
	allowPeers   map[string]bool
}

type nodeIdentity struct {
	platform string // ratls platform vocabulary: sev-snp or tdx
	policy   compiledNodePolicy
}

func loadNodePolicyFile(path string) (*nodePolicyRegistry, error) {
	if path == "" {
		return nil, nil
	}
	if err := policyFileReadOnly(path); err != nil {
		return nil, fmt.Errorf("--policy-file must be on a read-only filesystem: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --policy-file: %w", err)
	}
	var file nodePolicyFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse --policy-file: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse --policy-file: multiple JSON values")
		}
		return nil, fmt.Errorf("parse --policy-file trailing data: %w", err)
	}
	if file.Version != nodePolicyFileVersion {
		return nil, fmt.Errorf("--policy-file version %d is unsupported (want %d)", file.Version, nodePolicyFileVersion)
	}
	if len(file.Platforms) == 0 {
		return nil, fmt.Errorf("--policy-file has no platform policies")
	}

	r := &nodePolicyRegistry{byPlatform: make(map[string]compiledNodePolicy, len(file.Platforms))}
	rawPeers := make(map[string][]string, len(file.Platforms))
	for _, raw := range file.Platforms {
		platform, err := canonicalNodePlatform(raw.Platform)
		if err != nil {
			return nil, fmt.Errorf("--policy-file platform: %w", err)
		}
		if _, exists := r.byPlatform[platform]; exists {
			return nil, fmt.Errorf("--policy-file has duplicate %s policy", platform)
		}
		if len(raw.Measurements) == 0 {
			return nil, fmt.Errorf("--policy-file %s policy has no measurements", platform)
		}
		if len(raw.AllowPeers) == 0 {
			return nil, fmt.Errorf("--policy-file %s policy has no allow_peers", platform)
		}
		if platform == string(types.PlatformTdx) && raw.MinTCB != nil {
			// attestation-api has no TDX minimum-TCB request parameter. Reject
			// this instead of making a policy file appear stricter than it is.
			return nil, fmt.Errorf("--policy-file tdx policy cannot set min_tcb (not enforced for TDX)")
		}
		p := compiledNodePolicy{platform: platform, minTCB: raw.MinTCB}
		seenMeasurements := make(map[string]bool, len(raw.Measurements))
		for _, v := range raw.Measurements {
			measurement, err := parseNodeMeasurement(v)
			if err != nil {
				return nil, fmt.Errorf("--policy-file %s measurement: %w", platform, err)
			}
			key := hex.EncodeToString(measurement)
			if seenMeasurements[key] {
				return nil, fmt.Errorf("--policy-file %s has duplicate measurement %s", platform, key)
			}
			seenMeasurements[key] = true
			p.measurements = append(p.measurements, measurement)
		}
		if raw.TDX != nil {
			if platform != string(types.PlatformTdx) {
				return nil, fmt.Errorf("--policy-file %s policy has tdx profiles", platform)
			}
			if len(raw.TDX.Profiles) == 0 {
				return nil, fmt.Errorf("--policy-file tdx policy has an empty tdx.profiles list")
			}
			p.tdxProfiles = make(map[string]bool, len(raw.TDX.Profiles))
			for _, profile := range raw.TDX.Profiles {
				r1, err := parseNodeMeasurement(profile.RTMR1)
				if err != nil {
					return nil, fmt.Errorf("--policy-file tdx rtmr_1: %w", err)
				}
				r2, err := parseNodeMeasurement(profile.RTMR2)
				if err != nil {
					return nil, fmt.Errorf("--policy-file tdx rtmr_2: %w", err)
				}
				key := tdxProfileKey(hex.EncodeToString(r1), hex.EncodeToString(r2))
				if p.tdxProfiles[key] {
					return nil, fmt.Errorf("--policy-file tdx has duplicate rtmr profile")
				}
				p.tdxProfiles[key] = true
			}
		}
		r.byPlatform[platform] = p
		rawPeers[platform] = raw.AllowPeers
	}
	for platform, peers := range rawPeers {
		p := r.byPlatform[platform]
		p.allowPeers = make(map[string]bool, len(peers))
		for _, peer := range peers {
			canonical, err := canonicalNodePlatform(peer)
			if err != nil {
				return nil, fmt.Errorf("--policy-file %s allow_peers: %w", platform, err)
			}
			if _, registered := r.byPlatform[canonical]; !registered {
				return nil, fmt.Errorf("--policy-file %s allows unregistered peer platform %q", platform, canonical)
			}
			if p.allowPeers[canonical] {
				return nil, fmt.Errorf("--policy-file %s has duplicate allow_peers platform %q", platform, canonical)
			}
			p.allowPeers[canonical] = true
		}
		r.byPlatform[platform] = p
	}
	return r, nil
}

func canonicalNodePlatform(platform string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "snp", "sev-snp":
		return string(types.PlatformSnp), nil
	case "tdx":
		return string(types.PlatformTdx), nil
	default:
		return "", fmt.Errorf("unsupported native node platform %q (want snp or tdx)", platform)
	}
}

func parseNodeMeasurement(v string) ([]byte, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != measurementHexLen/2 {
		return nil, fmt.Errorf("must be a %d-character SHA-384 hex value", measurementHexLen)
	}
	return b, nil
}

func (r *nodePolicyRegistry) policyForEvidence(platform string) (compiledNodePolicy, error) {
	canonical, err := canonicalNodePlatform(platform)
	if err != nil {
		return compiledNodePolicy{}, err
	}
	p, ok := r.byPlatform[canonical]
	if !ok {
		return compiledNodePolicy{}, fmt.Errorf("no policy registered for attested platform %q", canonical)
	}
	return p, nil
}

func (p compiledNodePolicy) evidencePolicy(reportData [64]byte) attestationclient.EvidencePolicy {
	return attestationclient.EvidencePolicy{
		ExpectedReportData: reportData,
		AllowDebug:         false,
		MinTcb:             p.minTCB,
		Measurements:       p.measurements,
	}
}

// ownNodeIdentity attests and verifies the local node before it may either
// release or receive a join token. The response's platform only selects a
// preconfigured policy; VerifyEvidence then verifies that evidence under the
// selected platform's hardware rules and binds it to this fresh nonce.
func ownNodeIdentity(ctx context.Context, api attestationclient.Client, policies *nodePolicyRegistry) (nodeIdentity, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nodeIdentity{}, fmt.Errorf("join: generate nonce: %w", err)
	}
	attResp, err := api.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(nonce),
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		return nodeIdentity{}, fmt.Errorf("join: attest own evidence: %w", err)
	}
	p, err := policies.policyForEvidence(attResp.Platform)
	if err != nil {
		return nodeIdentity{}, fmt.Errorf("join: own attested platform: %w", err)
	}
	var expected [64]byte
	copy(expected[:], nonce)
	resp, err := api.VerifyEvidence(ctx, types.AttestationEvidence(attResp), p.evidencePolicy(expected))
	if err != nil {
		return nodeIdentity{}, fmt.Errorf("join: verify own evidence: %w", err)
	}
	verifiedPlatform, err := canonicalNodePlatform(resp.Result.Platform)
	if err != nil || verifiedPlatform != p.platform {
		return nodeIdentity{}, fmt.Errorf("join: own verified platform %q does not match selected policy %q", resp.Result.Platform, p.platform)
	}
	if err := p.enforceClaims(resp.Result.Claims); err != nil {
		return nodeIdentity{}, fmt.Errorf("join: own claims: %w", err)
	}
	return nodeIdentity{platform: ratls.NormalizePlatform(p.platform), policy: p}, nil
}

func (p compiledNodePolicy) enforceClaims(claims types.Claims) error {
	if p.platform != string(types.PlatformTdx) || len(p.tdxProfiles) == 0 {
		return nil
	}
	var pd tdxPlatformData
	if err := json.Unmarshal(claims.PlatformData, &pd); err != nil {
		return fmt.Errorf("parse TDX platform_data: %w", err)
	}
	r1, err := parseNodeMeasurement(pd.Rtmr1)
	if err != nil {
		return fmt.Errorf("TDX rtmr_1: %w", err)
	}
	r2, err := parseNodeMeasurement(pd.Rtmr2)
	if err != nil {
		return fmt.Errorf("TDX rtmr_2: %w", err)
	}
	if !p.tdxProfiles[tdxProfileKey(hex.EncodeToString(r1), hex.EncodeToString(r2))] {
		return fmt.Errorf("%w: TDX RTMR profile", ErrPolicyMismatch)
	}
	return nil
}

func tdxProfileKey(r1, r2 string) string { return r1 + ":" + r2 }

// verifyRegisteredPeer verifies a peer against the policy bound to the
// platform named in its RA-TLS evidence. That name is not trusted: it is only
// a selector into a fixed registry, and VerifyEvidence proves the envelope.
func verifyRegisteredPeer(ctx context.Context, api attestationclient.Client, leaf *x509.Certificate, own nodeIdentity, policies *nodePolicyRegistry) error {
	now := time.Now()
	if now.Add(certSkew).Before(leaf.NotBefore) || now.Add(-certSkew).After(leaf.NotAfter) {
		return fmt.Errorf("join: peer cert outside its validity window (%s .. %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	att, err := ratls.ExtractAttestation(leaf)
	if err != nil {
		return fmt.Errorf("join: peer cert: %w", err)
	}
	evidence, err := nodeEvidence(att)
	if err != nil {
		return fmt.Errorf("join: peer cert evidence: %w", err)
	}
	p, err := policies.policyForEvidence(evidence.Platform)
	if err != nil {
		return fmt.Errorf("join: peer platform policy: %w", err)
	}
	if (p.platform == string(types.PlatformSnp) && att.TEEType != ratls.TEETypeSEVSNP) ||
		(p.platform == string(types.PlatformTdx) && att.TEEType != ratls.TEETypeTDX) {
		return fmt.Errorf("join: RA-TLS TEE type does not match peer evidence platform %q", p.platform)
	}
	if !own.policy.allowPeers[p.platform] {
		return fmt.Errorf("%w: %s policy does not allow %s peers", ErrPolicyMismatch, own.policy.platform, p.platform)
	}
	rd, err := ratls.ReportDataForKey(leaf.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("join: compute expected report_data: %w", err)
	}
	resp, err := api.VerifyEvidence(ctx, evidence, p.evidencePolicy(rd))
	if err != nil {
		return fmt.Errorf("join: verify peer evidence: %w", err)
	}
	verifiedPlatform, err := canonicalNodePlatform(resp.Result.Platform)
	if err != nil || verifiedPlatform != p.platform {
		return fmt.Errorf("join: peer verified platform %q does not match selected policy %q", resp.Result.Platform, p.platform)
	}
	if err := p.enforceClaims(resp.Result.Claims); err != nil {
		return fmt.Errorf("join: peer claims: %w", err)
	}
	return nil
}

// nodeEvidence exposes both RA-TLS forms accepted for native nodes. Bare-metal
// SNP intentionally carries its raw 1184-byte report so it remains usable by
// offline SNP verifiers. c8s delegates its online verification to the local
// attestation-api, which expects that raw report wrapped in this evidence
// envelope. TDX must carry an envelope because c8s has no in-process TDX
// quote parser.
func nodeEvidence(att *ratls.Attestation) (types.AttestationEvidence, error) {
	if evidence, ok := att.EmbeddedEvidence(); ok {
		return evidence, nil
	}
	if att.TEEType != ratls.TEETypeSEVSNP {
		return types.AttestationEvidence{}, fmt.Errorf("missing attestation evidence envelope")
	}
	inner, err := json.Marshal(struct {
		AttestationReport string `json:"attestation_report"`
	}{AttestationReport: base64.StdEncoding.EncodeToString(att.Report)})
	if err != nil {
		return types.AttestationEvidence{}, fmt.Errorf("wrap raw SNP report: %w", err)
	}
	return types.AttestationEvidence{Platform: string(types.PlatformSnp), Evidence: inner}, nil
}
