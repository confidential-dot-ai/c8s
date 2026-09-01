package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	attestationCLIVersion = "attestation-cli 0.5.0"
	maxGPUVerifierOutput  = 2 << 20
)

type gpuVerdict struct {
	Verified       bool
	NonceBindingOK bool
	DeviceUEIDs    []string
}

type gpuVerifierResult struct {
	SignatureValid  bool  `json:"signature_valid"`
	ReportDataMatch *bool `json:"report_data_match"`
	Claims          struct {
		NvidiaGPU *struct {
			OverallOK      bool `json:"overall_ok"`
			NonceBindingOK bool `json:"nonce_binding_ok"`
			Devices        []struct {
				UEID string `json:"ueid"`
				Arch string `json:"arch"`
			} `json:"devices"`
		} `json:"nvidia_gpu"`
	} `json:"claims"`
}

func validateNvidiaGPUConfig(cfg config) error {
	if cfg.nvidiaGPURequired && cfg.nvidiaGPUUserNonce == "" {
		return fmt.Errorf("--nvidia-gpu-required requires --nvidia-gpu-user-nonce")
	}
	if len(cfg.nvidiaGPUExpectedArchs) != 0 && cfg.nvidiaGPUUserNonce == "" {
		return fmt.Errorf("--nvidia-gpu-expected-arch requires --nvidia-gpu-user-nonce")
	}
	if cfg.nvidiaGPUExpectedCount < 0 {
		return fmt.Errorf("--nvidia-gpu-expected-count must not be negative")
	}
	if cfg.nvidiaGPUExpectedCount != 0 && cfg.nvidiaGPUUserNonce == "" {
		return fmt.Errorf("--nvidia-gpu-expected-count requires --nvidia-gpu-user-nonce")
	}
	for _, arch := range cfg.nvidiaGPUExpectedArchs {
		switch arch {
		case "HOPPER", "BLACKWELL", "LS10":
		default:
			return fmt.Errorf("--nvidia-gpu-expected-arch must be HOPPER, BLACKWELL, or LS10, got %q", arch)
		}
	}
	if cfg.nvidiaGPUUserNonce == "" {
		return nil
	}
	nonce, err := hex.DecodeString(cfg.nvidiaGPUUserNonce)
	if err != nil {
		return fmt.Errorf("--nvidia-gpu-user-nonce must be hex: %w", err)
	}
	if len(nonce) < 16 || len(nonce) > 64 {
		return fmt.Errorf("--nvidia-gpu-user-nonce must decode to 16 through 64 bytes, got %d", len(nonce))
	}
	if cfg.nvidiaGPUUserNonce != strings.ToLower(cfg.nvidiaGPUUserNonce) {
		return fmt.Errorf("--nvidia-gpu-user-nonce must use lowercase hex")
	}
	return nil
}

func verifyNvidiaGPU(ctx context.Context, cfg config, ev *evidence) (*gpuVerdict, error) {
	raw := bytes.TrimSpace(ev.nvidiaGPU)
	hasBundle := len(raw) != 0 && !bytes.Equal(raw, []byte("null"))
	if !hasBundle {
		if cfg.nvidiaGPURequired {
			return nil, fmt.Errorf("the receipt has no NVIDIA GPU evidence")
		}
		return nil, nil
	}
	if cfg.nvidiaGPUUserNonce == "" {
		return nil, nil
	}
	if ev.gpuAttested != types.GPUAttestedEvidenceCollected {
		return nil, fmt.Errorf("GPU collection state is %q, want %q", ev.gpuAttested, types.GPUAttestedEvidenceCollected)
	}
	nonce, _ := hex.DecodeString(cfg.nvidiaGPUUserNonce)
	if !bytes.Equal(nonce, ev.erd) {
		return nil, fmt.Errorf("GPU user nonce does not equal the CPU report-data transcript")
	}

	envelope, err := json.Marshal(struct {
		Platform  string          `json:"platform"`
		Evidence  json.RawMessage `json:"evidence"`
		NvidiaGPU json.RawMessage `json:"nvidia_gpu"`
	}{Platform: ev.platform, Evidence: ev.rawEvidence, NvidiaGPU: ev.nvidiaGPU})
	if err != nil {
		return nil, fmt.Errorf("encode GPU evidence envelope: %w", err)
	}

	path := cfg.attestationCLIPath
	if path == "" {
		path, err = exec.LookPath("attestation-cli")
		if err != nil {
			return nil, fmt.Errorf("attestation-cli v0.5.0 is required for NVIDIA NRAS verification: %w", err)
		}
	}
	version, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil || strings.TrimSpace(string(version)) != attestationCLIVersion {
		return nil, fmt.Errorf("NVIDIA verifier must be %q, got %q", attestationCLIVersion, strings.TrimSpace(string(version)))
	}

	args := []string{"verify", "--nvidia-gpu-user-nonce", cfg.nvidiaGPUUserNonce}
	if cfg.nvidiaGPURequired {
		args = append(args, "--nvidia-gpu-required")
	}
	if len(cfg.nvidiaGPUExpectedArchs) != 0 {
		args = append(args, "--nvidia-gpu-expected-archs", strings.Join(cfg.nvidiaGPUExpectedArchs, ","))
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(envelope)
	var stdout, stderr cappedBuffer
	stdout.limit = maxGPUVerifierOutput
	stderr.limit = maxGPUVerifierOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("attestation-cli rejected NVIDIA evidence: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var result gpuVerifierResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse attestation-cli result: %w", err)
	}
	if !result.SignatureValid || result.ReportDataMatch == nil || !*result.ReportDataMatch {
		return nil, fmt.Errorf("attestation-cli did not verify the CPU evidence and report-data binding")
	}
	if result.Claims.NvidiaGPU == nil || !result.Claims.NvidiaGPU.OverallOK || !result.Claims.NvidiaGPU.NonceBindingOK {
		return nil, fmt.Errorf("attestation-cli did not verify the NVIDIA evidence and nonce binding")
	}
	devices := result.Claims.NvidiaGPU.Devices
	if len(devices) == 0 {
		return nil, fmt.Errorf("attestation-cli returned no signed NVIDIA device identities")
	}
	ueids := make([]string, 0, len(devices))
	seen := make(map[string]struct{}, len(devices))
	for i, device := range devices {
		ueid := strings.TrimSpace(device.UEID)
		if ueid == "" {
			return nil, fmt.Errorf("attestation-cli returned an empty signed NVIDIA device UEID at index %d", i)
		}
		if _, ok := seen[ueid]; ok {
			return nil, fmt.Errorf("attestation-cli returned duplicate signed NVIDIA device UEID")
		}
		seen[ueid] = struct{}{}
		ueids = append(ueids, ueid)
	}
	if cfg.nvidiaGPUExpectedCount != 0 && len(ueids) != cfg.nvidiaGPUExpectedCount {
		return nil, fmt.Errorf("verified NVIDIA device count is %d, want %d", len(ueids), cfg.nvidiaGPUExpectedCount)
	}
	return &gpuVerdict{Verified: true, NonceBindingOK: true, DeviceUEIDs: ueids}, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("verifier output exceeds %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}
