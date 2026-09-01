package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	attestationCLIVersion = "attestation-cli 0.5.0"
	attestationRSCommit   = "41ad0c5495ec3cf4dc7a69d2870084bdf6b92f98"
	maxGPUVerifierOutput  = 2 << 20
)

type gpuVerdict struct {
	Verified                    bool
	NonceBindingOK              bool
	GPUDeviceUEIDs              []string
	SwitchDeviceUEIDs           []string
	VerifierSHA256              string
	VerifierAttestationRSCommit string
}

type gpuVerifierResult struct {
	SignatureValid  bool  `json:"signature_valid"`
	ReportDataMatch *bool `json:"report_data_match"`
	Claims          struct {
		NvidiaGPU *struct {
			OverallOK      bool `json:"overall_ok"`
			NonceBindingOK bool `json:"nonce_binding_ok"`
			Devices        []struct {
				UEID    string `json:"ueid"`
				Arch    string `json:"arch"`
				HWModel string `json:"hwmodel"`
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
	if cfg.nvidiaSwitchExpectedCount < 0 {
		return fmt.Errorf("--nvidia-switch-expected-count must not be negative")
	}
	if cfg.nvidiaGPUExpectedCount != 0 && cfg.nvidiaGPUUserNonce == "" {
		return fmt.Errorf("--nvidia-gpu-expected-count requires --nvidia-gpu-user-nonce")
	}
	if cfg.nvidiaSwitchExpectedCount != 0 && cfg.nvidiaGPUUserNonce == "" {
		return fmt.Errorf("--nvidia-switch-expected-count requires --nvidia-gpu-user-nonce")
	}
	for _, arch := range cfg.nvidiaGPUExpectedArchs {
		switch arch {
		case "HOPPER", "BLACKWELL":
		default:
			return fmt.Errorf("--nvidia-gpu-expected-arch must be HOPPER or BLACKWELL, got %q", arch)
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
	if len(cfg.attestationCLISHA256) != sha256.Size*2 {
		return fmt.Errorf("--attestation-cli-sha256 must be one lowercase SHA-256 digest")
	}
	if _, err := hex.DecodeString(cfg.attestationCLISHA256); err != nil || cfg.attestationCLISHA256 != strings.ToLower(cfg.attestationCLISHA256) {
		return fmt.Errorf("--attestation-cli-sha256 must be one lowercase SHA-256 digest")
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
	verifierBytes, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, fmt.Errorf("read NVIDIA verifier: %w", readErr)
	}
	verifierSum := sha256.Sum256(verifierBytes)
	verifierDigest := hex.EncodeToString(verifierSum[:])
	if verifierDigest != cfg.attestationCLISHA256 {
		return nil, fmt.Errorf("NVIDIA verifier SHA-256 is %q, want %q", verifierDigest, cfg.attestationCLISHA256)
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
		// attestation-rs verifies raw evidence groups. c8s also compares these
		// groups with the architecture derived from each signed hwmodel below.
		args = append(args, "--nvidia-gpu-expected-archs", strings.Join(append(append([]string(nil), cfg.nvidiaGPUExpectedArchs...), "LS10"), ","))
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
	var rawBundle struct {
		Devices []struct {
			Arch string `json:"arch"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(ev.nvidiaGPU, &rawBundle); err != nil {
		return nil, fmt.Errorf("parse raw NVIDIA evidence inventory: %w", err)
	}
	rawArchCounts := make(map[string]int)
	for i, device := range rawBundle.Devices {
		arch := strings.ToUpper(strings.TrimSpace(device.Arch))
		switch arch {
		case "HOPPER", "BLACKWELL", "LS10":
			rawArchCounts[arch]++
		default:
			return nil, fmt.Errorf("raw NVIDIA evidence has unsupported architecture %q at index %d", device.Arch, i)
		}
	}
	signedArchCounts := make(map[string]int)
	gpuUEIDs := make([]string, 0, len(devices))
	switchUEIDs := make([]string, 0, len(devices))
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
		arch := archFromSignedHWModel(device.HWModel)
		if arch == "" {
			return nil, fmt.Errorf("attestation-cli returned an unrecognized signed NVIDIA hwmodel %q at index %d", device.HWModel, i)
		}
		if strings.ToUpper(strings.TrimSpace(device.Arch)) != arch {
			return nil, fmt.Errorf("signed NVIDIA hwmodel architecture %q does not match verifier architecture %q", arch, device.Arch)
		}
		signedArchCounts[arch]++
		if arch == "LS10" {
			switchUEIDs = append(switchUEIDs, ueid)
		} else {
			gpuUEIDs = append(gpuUEIDs, ueid)
		}
	}
	if !archCountsEqual(rawArchCounts, signedArchCounts) {
		return nil, fmt.Errorf("signed NVIDIA hwmodel architectures do not match raw evidence groups")
	}
	if cfg.nvidiaGPUExpectedCount != 0 && len(gpuUEIDs) != cfg.nvidiaGPUExpectedCount {
		return nil, fmt.Errorf("verified NVIDIA GPU count is %d, want %d", len(gpuUEIDs), cfg.nvidiaGPUExpectedCount)
	}
	if cfg.nvidiaSwitchExpectedCount != 0 && len(switchUEIDs) != cfg.nvidiaSwitchExpectedCount {
		return nil, fmt.Errorf("verified NVIDIA switch count is %d, want %d", len(switchUEIDs), cfg.nvidiaSwitchExpectedCount)
	}
	return &gpuVerdict{
		Verified: true, NonceBindingOK: true,
		GPUDeviceUEIDs: gpuUEIDs, SwitchDeviceUEIDs: switchUEIDs,
		VerifierSHA256: verifierDigest, VerifierAttestationRSCommit: attestationRSCommit,
	}, nil
}

func archFromSignedHWModel(model string) string {
	upper := strings.ToUpper(strings.TrimSpace(model))
	switch {
	case strings.Contains(upper, "HOPPER"), strings.HasPrefix(upper, "GH100"):
		return "HOPPER"
	case strings.Contains(upper, "BLACKWELL"), strings.HasPrefix(upper, "GB"):
		return "BLACKWELL"
	case strings.Contains(upper, "LS10"), strings.Contains(upper, "SWITCH"):
		return "LS10"
	default:
		return ""
	}
}

func archCountsEqual(a, b map[string]int) bool {
	for _, arch := range []string{"HOPPER", "BLACKWELL", "LS10"} {
		if a[arch] != b[arch] {
			return false
		}
	}
	return true
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
