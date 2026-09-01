package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestVerifyNvidiaGPUUsesPinnedVerifierAndNonce(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	path := writeGPUVerifier(t, `
[ "$5" = "--nvidia-gpu-expected-archs" ]
[ "$6" = "BLACKWELL,LS10" ]
`, `{
  "signature_valid": true,
  "report_data_match": true,
  "claims": {"nvidia_gpu": {"overall_ok": true, "nonce_binding_ok": true,
    "devices": [{"ueid":"gpu-a","arch":"BLACKWELL","hwmodel":"GB200 BLACKWELL"},{"ueid":"gpu-b","arch":"BLACKWELL","hwmodel":"GB200 BLACKWELL"}]}}
}`)
	ev := &evidence{
		platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"BLACKWELL"},{"arch":"BLACKWELL"}],"binding":{"concat":{"algo":"sha256"}}}`),
		gpuAttested: types.GPUAttestedEvidenceCollected,
		erd:         mustDecodeHex(t, nonceHex),
	}
	got, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce:     nonceHex,
		nvidiaGPURequired:      true,
		nvidiaGPUExpectedArchs: []string{"BLACKWELL"},
		nvidiaGPUExpectedCount: 2,
		attestationCLIPath:     path,
		attestationCLISHA256:   verifierDigest(t, path),
	}, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Verified || !got.NonceBindingOK || len(got.GPUDeviceUEIDs) != 2 || len(got.SwitchDeviceUEIDs) != 0 {
		t.Fatalf("GPU verdict = %+v", got)
	}
}

func TestVerifyNvidiaGPURejectsDuplicateOrMissingSignedDeviceIdentity(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	for _, tc := range []struct {
		name    string
		devices string
		want    string
	}{
		{name: "duplicate UEID", devices: `[{"ueid":"gpu-a","arch":"BLACKWELL","hwmodel":"GB200"},{"ueid":"gpu-a","arch":"BLACKWELL","hwmodel":"GB200"}]`, want: "duplicate signed NVIDIA device UEID"},
		{name: "empty UEID", devices: `[{"ueid":"","arch":"BLACKWELL","hwmodel":"GB200"}]`, want: "empty signed NVIDIA device UEID"},
		{name: "no devices", devices: `[]`, want: "no signed NVIDIA device identities"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := `{"signature_valid":true,"report_data_match":true,"claims":{"nvidia_gpu":{"overall_ok":true,"nonce_binding_ok":true,"devices":` + tc.devices + `}}}`
			path := writeGPUVerifier(t, "", result)
			_, err := verifyNvidiaGPU(context.Background(), config{
				nvidiaGPUUserNonce:   nonceHex,
				nvidiaGPURequired:    true,
				attestationCLIPath:   path,
				attestationCLISHA256: verifierDigest(t, path),
			}, &evidence{
				platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
				// A repeated raw device blob must not inflate the verified count.
				nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"BLACKWELL","uuid":"untrusted"},{"arch":"BLACKWELL","uuid":"untrusted"}]}`),
				gpuAttested: types.GPUAttestedEvidenceCollected,
				erd:         mustDecodeHex(t, nonceHex),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyNvidiaGPUEnforcesSignedDeviceCount(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	path := writeGPUVerifier(t, "", `{
  "signature_valid": true,
  "report_data_match": true,
  "claims": {"nvidia_gpu": {"overall_ok": true, "nonce_binding_ok": true,
    "devices": [{"ueid":"gpu-a","arch":"BLACKWELL","hwmodel":"GB200 BLACKWELL"}]}}
}`)
	_, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true,
		nvidiaGPUExpectedCount: 2, attestationCLIPath: path, attestationCLISHA256: verifierDigest(t, path),
	}, &evidence{
		platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU: json.RawMessage(`{"devices":[{"arch":"BLACKWELL"}]}`), gpuAttested: types.GPUAttestedEvidenceCollected,
		erd: mustDecodeHex(t, nonceHex),
	})
	if err == nil || !strings.Contains(err.Error(), "verified NVIDIA GPU count is 1, want 2") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyNvidiaGPUFailsClosed(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	nonce := mustDecodeHex(t, nonceHex)
	validBundle := json.RawMessage(`{"devices":[{"arch":"BLACKWELL"}]}`)
	for _, tc := range []struct {
		name string
		cfg  config
		ev   *evidence
		want string
	}{
		{
			name: "required bundle absent",
			cfg:  config{nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true},
			ev:   &evidence{erd: nonce},
			want: "no NVIDIA GPU evidence",
		},
		{
			name: "collection state is not evidence collected",
			cfg:  config{nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true},
			ev:   &evidence{erd: nonce, nvidiaGPU: validBundle, gpuAttested: types.GPUAttestedUnknown},
			want: "collection state",
		},
		{
			name: "GPU nonce differs from CPU transcript",
			cfg:  config{nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true},
			ev:   &evidence{erd: append([]byte{0}, nonce...), nvidiaGPU: validBundle, gpuAttested: types.GPUAttestedEvidenceCollected},
			want: "does not equal",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyNvidiaGPU(context.Background(), tc.cfg, tc.ev); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyNvidiaGPURejectsUnverifiedClaims(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	path := writeGPUVerifier(t, "", `{
  "signature_valid": true,
  "report_data_match": true,
  "claims": {"nvidia_gpu": {"overall_ok": true, "nonce_binding_ok": false}}
}`)
	_, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce:   nonceHex,
		nvidiaGPURequired:    true,
		attestationCLIPath:   path,
		attestationCLISHA256: verifierDigest(t, path),
	}, &evidence{
		platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU:   json.RawMessage(`{"devices":[{}]}`),
		gpuAttested: types.GPUAttestedEvidenceCollected,
		erd:         mustDecodeHex(t, nonceHex),
	})
	if err == nil || !strings.Contains(err.Error(), "did not verify the NVIDIA evidence") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyNvidiaGPURejectsUnexpectedArchitecture(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	path := writeGPUVerifier(t, `
[ "$5" = "--nvidia-gpu-expected-archs" ]
[ "$6" = "BLACKWELL,LS10" ]
echo "GPU architecture is not in the expected set" >&2
exit 1
`, "")
	_, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce:     nonceHex,
		nvidiaGPURequired:      true,
		nvidiaGPUExpectedArchs: []string{"BLACKWELL"},
		attestationCLIPath:     path,
		attestationCLISHA256:   verifierDigest(t, path),
	}, &evidence{
		platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"HOPPER"}]}`),
		gpuAttested: types.GPUAttestedEvidenceCollected,
		erd:         mustDecodeHex(t, nonceHex),
	})
	if err == nil || !strings.Contains(err.Error(), "GPU architecture is not in the expected set") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyNvidiaGPUSeparatesGPUsAndSwitches(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	path := writeGPUVerifier(t, "", `{
  "signature_valid": true,
  "report_data_match": true,
  "claims": {"nvidia_gpu": {"overall_ok": true, "nonce_binding_ok": true,
    "devices": [
      {"ueid":"gpu-a","arch":"BLACKWELL","hwmodel":"GB200 BLACKWELL"},
      {"ueid":"gpu-b","arch":"BLACKWELL","hwmodel":"GB200 BLACKWELL"},
      {"ueid":"switch-a","arch":"LS10","hwmodel":"LS10 NVSwitch"}
    ]}}
}`)
	got, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true,
		nvidiaGPUExpectedCount: 2, nvidiaSwitchExpectedCount: 1,
		attestationCLIPath: path, attestationCLISHA256: verifierDigest(t, path),
	}, &evidence{
		platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"BLACKWELL"},{"arch":"BLACKWELL"},{"arch":"LS10"}]}`),
		gpuAttested: types.GPUAttestedEvidenceCollected, erd: mustDecodeHex(t, nonceHex),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GPUDeviceUEIDs) != 2 || len(got.SwitchDeviceUEIDs) != 1 {
		t.Fatalf("separated verdict = %+v", got)
	}
}

func TestVerifyNvidiaGPURequiresSignedHWModelAndRawMatch(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	tests := []struct {
		name    string
		hwmodel string
		rawArch string
		want    string
	}{
		{name: "missing signed architecture", hwmodel: "unknown model", rawArch: "BLACKWELL", want: "unrecognized signed NVIDIA hwmodel"},
		{name: "raw architecture mismatch", hwmodel: "GB200 BLACKWELL", rawArch: "HOPPER", want: "do not match raw evidence groups"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := `{"signature_valid":true,"report_data_match":true,"claims":{"nvidia_gpu":{"overall_ok":true,"nonce_binding_ok":true,"devices":[{"ueid":"device-a","arch":"BLACKWELL","hwmodel":"` + tc.hwmodel + `"}]}}}`
			path := writeGPUVerifier(t, "", result)
			_, err := verifyNvidiaGPU(context.Background(), config{
				nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true,
				attestationCLIPath: path, attestationCLISHA256: verifierDigest(t, path),
			}, &evidence{
				platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
				nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"` + tc.rawArch + `"}]}`),
				gpuAttested: types.GPUAttestedEvidenceCollected, erd: mustDecodeHex(t, nonceHex),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyNvidiaGPURejectsWrongVerifierDigest(t *testing.T) {
	nonceHex := strings.Repeat("ab", 48)
	path := writeGPUVerifier(t, "", "{}")
	_, err := verifyNvidiaGPU(context.Background(), config{
		nvidiaGPUUserNonce: nonceHex, nvidiaGPURequired: true,
		attestationCLIPath: path, attestationCLISHA256: strings.Repeat("00", sha256.Size),
	}, &evidence{
		platform: "tdx", rawEvidence: json.RawMessage(`{"quote":"cpu"}`),
		nvidiaGPU:   json.RawMessage(`{"devices":[{"arch":"BLACKWELL"}]}`),
		gpuAttested: types.GPUAttestedEvidenceCollected, erd: mustDecodeHex(t, nonceHex),
	})
	if err == nil || !strings.Contains(err.Error(), "verifier SHA-256") {
		t.Fatalf("error = %v, want verifier digest rejection", err)
	}
}

func TestAttestationRSCommitMatchesGuestProducerLock(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "node-guest-image", "attestation-rs.ref"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != attestationRSCommit {
		t.Fatalf("attestation-rs source lock = %q, verifier reports %q", got, attestationRSCommit)
	}
}

func TestValidateNvidiaGPUConfig(t *testing.T) {
	for _, tc := range []config{
		{nvidiaGPURequired: true},
		{nvidiaGPUExpectedArchs: []string{"BLACKWELL"}},
		{nvidiaGPUExpectedCount: -1},
		{nvidiaSwitchExpectedCount: -1},
		{nvidiaGPUExpectedCount: 8},
		{nvidiaGPUUserNonce: strings.Repeat("ab", 48), nvidiaGPUExpectedArchs: []string{"LS10"}},
		{nvidiaGPUUserNonce: strings.Repeat("ab", 48), nvidiaGPUExpectedArchs: []string{"BLACKWELL", "AMPERE"}},
		{nvidiaGPUUserNonce: "zz"},
		{nvidiaGPUUserNonce: strings.Repeat("ab", 15)},
		{nvidiaGPUUserNonce: strings.Repeat("AB", 16)},
	} {
		if err := validateNvidiaGPUConfig(tc); err == nil {
			t.Fatalf("invalid config passed: %+v", tc)
		}
	}
	if err := validateNvidiaGPUConfig(config{nvidiaGPUUserNonce: strings.Repeat("ab", 48), nvidiaGPURequired: true}); err != nil {
		if !strings.Contains(err.Error(), "--attestation-cli-sha256") {
			t.Fatal(err)
		}
	}
	if err := validateNvidiaGPUConfig(config{nvidiaGPUUserNonce: strings.Repeat("ab", 48), nvidiaGPURequired: true, attestationCLISHA256: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
}

func writeGPUVerifier(t *testing.T, extraChecks, result string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attestation-cli")
	script := `#!/bin/sh
set -eu
if [ "$1" = "--version" ]; then
  echo "attestation-cli 0.5.0"
  exit 0
fi
[ "$1" = "verify" ]
[ "$2" = "--nvidia-gpu-user-nonce" ]
[ "$4" = "--nvidia-gpu-required" ]
` + extraChecks + `
grep -q '"nvidia_gpu"'
printf '%s\n' '` + result + `'
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func verifierDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
