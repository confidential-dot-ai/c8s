package cdsattest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// CollectedEvidence carries CPU evidence and an optional NVIDIA bundle.
// NvidiaGPU stays opaque so c8s preserves the attestation-rs bundle shape.
type CollectedEvidence struct {
	Evidence    json.RawMessage
	Platform    string
	Generation  string
	GPUAttested string
	NvidiaGPU   json.RawMessage
}

// EvidenceProvider yields evidence whose report_data equals the endpoint's
// transcript hash. It also returns raw NVIDIA evidence when requested. The
// attestation-api derives every GPU nonce from the same report_data. Thus the
// CPU TEE and all GPUs commit to one client request.
type EvidenceProvider interface {
	Evidence(ctx context.Context, reportData []byte) (CollectedEvidence, error)
}

var _ EvidenceProvider = LiveEvidenceProvider{}

// LiveEvidenceProvider asks the local attestation-api for a fresh report
// bound to reportData. This is the production path. It calls the attestation
// API in the same node CVM. A GPU-worker receipt sidecar can enable GPU
// collection for that node. A TLS-LB on a different node must not claim those
// GPUs.
type LiveEvidenceProvider struct {
	Client            attestationclient.Client
	Platform          types.Platform // e.g. types.PlatformSnp
	NvidiaGPUEvidence bool
	// Generation is the AMD processor generation the browser's bare-SNP
	// verifier needs. It is meaningful only for PlatformSnp; the other
	// platforms auto-detect (az-snp) or have no generation concept (TDX),
	// and the bundle field is left empty for them.
	Generation string
}

// Evidence implements EvidenceProvider against the attestation-api.
func (p LiveEvidenceProvider) Evidence(ctx context.Context, reportData []byte) (CollectedEvidence, error) {
	resp, err := p.Client.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportData),
		Platform:   p.Platform,
		NvidiaGPU:  p.NvidiaGPUEvidence,
	})
	if err != nil {
		return CollectedEvidence{}, fmt.Errorf("attestation-api: %w", err)
	}
	platform := resp.Platform
	if platform == "" {
		platform = string(p.Platform)
	}
	generation := p.Generation
	if platform != string(types.PlatformSnp) {
		generation = ""
	}
	if err := validateGPUCollection(resp, p.NvidiaGPUEvidence); err != nil {
		return CollectedEvidence{}, fmt.Errorf("attestation-api: %w", err)
	}
	return CollectedEvidence{
		Evidence:    resp.Evidence,
		Platform:    platform,
		Generation:  generation,
		GPUAttested: normalizedGPUStatus(resp.GPUAttested),
		NvidiaGPU:   resp.NvidiaGPU,
	}, nil
}

func normalizedGPUStatus(status string) string {
	if status == "" {
		return types.GPUAttestedUnknown
	}
	return status
}

func validateGPUCollection(resp types.AttestResponse, required bool) error {
	status := normalizedGPUStatus(resp.GPUAttested)
	raw := bytes.TrimSpace(resp.NvidiaGPU)
	hasBundle := len(raw) != 0 && !bytes.Equal(raw, []byte("null"))
	switch status {
	case types.GPUAttestedUnknown:
		if hasBundle {
			return fmt.Errorf("GPU status is unknown but the response carries a bundle")
		}
	case types.GPUAttestedEvidenceCollected:
		if !hasBundle {
			return fmt.Errorf("GPU status says evidence_collected but the response carries no bundle")
		}
	default:
		return fmt.Errorf("unsupported GPU collection status %q", resp.GPUAttested)
	}
	if required && status != types.GPUAttestedEvidenceCollected {
		return fmt.Errorf("GPU evidence was requested but the service did not collect it")
	}
	return nil
}

// FixtureEvidenceProvider serves a recorded evidence file. DEV/DEMO ONLY: the
// recorded report_data is fixed, so it cannot bind a live session key+nonce —
// clients must run with freshness enforcement downgraded. It exists so the LB
// can serve the full contract (and interoperate with the JS client) without a
// TEE, mirroring c8s's test/mock-cds.
type FixtureEvidenceProvider struct {
	Raw        json.RawMessage
	Platform   string
	Generation string
}

// LoadFixtureEvidence reads a recorded evidence JSON file. The file may be the
// bare SnpEvidence object or a {platform, evidence} envelope.
func LoadFixtureEvidence(path, platform, generation string) (FixtureEvidenceProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureEvidenceProvider{}, fmt.Errorf("read evidence fixture: %w", err)
	}
	var env struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	evidence := json.RawMessage(raw)
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Evidence) > 0 {
		evidence = env.Evidence
		if platform == "" {
			platform = env.Platform
		}
	}
	if platform == "" {
		platform = "snp"
	}
	if platform != string(types.PlatformSnp) {
		generation = ""
	}
	return FixtureEvidenceProvider{Raw: evidence, Platform: platform, Generation: generation}, nil
}

// Evidence implements EvidenceProvider; reportData is ignored (see type doc).
func (p FixtureEvidenceProvider) Evidence(_ context.Context, _ []byte) (CollectedEvidence, error) {
	return CollectedEvidence{
		Evidence:    p.Raw,
		Platform:    p.Platform,
		Generation:  p.Generation,
		GPUAttested: types.GPUAttestedUnknown,
	}, nil
}
