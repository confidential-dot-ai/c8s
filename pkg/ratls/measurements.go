package ratls

import (
	"encoding/hex"
	"fmt"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"strconv"
	"strings"
)

// Pins is the peer-identity pin set an in-cluster RA-TLS verifier enforces:
// the launch-measurement reference values and, for TDX peers, the runtime
// measurement registers. The zero value pins nothing (accept any attested
// TEE — development only; callers warn).
type Pins struct {
	// Measurements is the set of acceptable launch measurements
	// (VerifyPolicy.Measurements).
	Measurements [][]byte
	// RTMRs pins TDX runtime measurement registers by index
	// (VerifyPolicy.RTMRs). Ignored on SNP evidence, where kernel-hashes
	// folds the guest image into the launch digest.
	RTMRs map[int][]byte
	// PCRs pins Azure vTPM registers by index (VerifyPolicy.PCRs). Ignored
	// on platforms without a vTPM.
	PCRs map[int][]byte
	// InitDataHash pins the SHA-256 init-data digest
	// (VerifyPolicy.InitDataHash): bound via vTPM PCR[8] on az-snp/az-tdx,
	// HOST_DATA on snp, MRCONFIGID on tdx. Nil pins nothing.
	InitDataHash []byte

	// Entries pins whole images (VerifyPolicy.Entries). When set it replaces
	// Measurements and RTMRs, so a digest from one image cannot be paired
	// with another's registers.
	Entries []measurements.Entry
}

// VerifyPolicy converts the pins into the policy the verifying paths read.
// Every caller goes through here: a hand-copied conversion that forgets a
// field drops those pins while still compiling.
func (p Pins) VerifyPolicy(attestationApiURL string) *VerifyPolicy {
	return &VerifyPolicy{
		Entries:           p.Entries,
		Measurements:      p.Measurements,
		RTMRs:             p.RTMRs,
		PCRs:              p.PCRs,
		InitDataHash:      p.InitDataHash,
		AttestationApiURL: attestationApiURL,
	}
}

// ParseHexMeasurements parses a comma-separated list of hex-encoded SEV-SNP
// launch digests into the byte form VerifyPolicy.Measurements expects. Empty
// input returns nil; the caller decides whether to warn.
func ParseHexMeasurements(raw string) ([][]byte, error) {
	return ParseHexMeasurementsList(strings.Split(raw, ","))
}

// ParseHexMeasurementsList parses a slice of hex-encoded SEV-SNP launch
// digests into the byte form VerifyPolicy.Measurements expects. Blank entries
// are skipped; an all-blank or empty slice returns nil. The caller decides
// whether to warn on an empty result.
func ParseHexMeasurementsList(raw []string) ([][]byte, error) {
	out := make([][]byte, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		decoded, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid hex measurement %q: %w", p, err)
		}
		if len(decoded) != SNPMeasurementSize {
			return nil, fmt.Errorf("measurement %q is %d bytes, want %d", p, len(decoded), SNPMeasurementSize)
		}
		out = append(out, decoded)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ParseRTMRPins parses TDX RTMR pins of the form <index>=<sha384-hex> into
// the map VerifyPolicy.RTMRs expects. Blank entries are skipped; an all-blank
// or empty slice returns nil (no pin). Only indices 1, 2 and 3 are pinnable:
// RTMR[0] carries the TD HOB, so it varies with the pod's vCPU and memory
// shape and a pin on it would deny guests by size rather than by identity.
func ParseRTMRPins(raw []string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idxStr, hexStr, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("rtmr pin %q: want <index>=<sha384-hex>", p)
		}
		idx, err := strconv.Atoi(strings.TrimSpace(idxStr))
		if err != nil {
			return nil, fmt.Errorf("rtmr pin %q: index is not a number: %w", p, err)
		}
		switch idx {
		case 1, 2, 3:
		case 0:
			return nil, fmt.Errorf("RTMR[0] is not pinnable: it carries the TD HOB, so it varies with the pod's vCPU and memory shape")
		default:
			return nil, fmt.Errorf("rtmr pin %q: index must be 1, 2 or 3", p)
		}
		if _, dup := out[idx]; dup {
			return nil, fmt.Errorf("RTMR[%d] pinned more than once", idx)
		}
		v, err := hex.DecodeString(strings.TrimSpace(hexStr))
		if err != nil {
			return nil, fmt.Errorf("rtmr pin %d: value is not hex: %w", idx, err)
		}
		if len(v) != SNPMeasurementSize {
			return nil, fmt.Errorf("rtmr pin %d: value is %d bytes, want %d (%d hex characters)", idx, len(v), SNPMeasurementSize, SNPMeasurementSize*2)
		}
		out[idx] = v
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ParseRTMRPinsString parses a comma-separated list of <index>=<sha384-hex>
// RTMR pins (see ParseRTMRPins). Empty input returns nil.
func ParseRTMRPinsString(raw string) (map[int][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return ParseRTMRPins(strings.Split(raw, ","))
}

// ParsePCRPins parses Azure vTPM PCR pins of the form <index>=<sha256-hex>
// into the map VerifyPolicy.PCRs expects. Blank entries are skipped; an
// all-blank or empty slice returns nil (no pin). Indices 0-23 are accepted —
// which registers carry guest identity depends on the measured-boot layout of
// the deployed node image.
func ParsePCRPins(raw []string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idxStr, hexStr, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("pcr pin %q: want <index>=<sha256-hex>", p)
		}
		idx, err := strconv.Atoi(strings.TrimSpace(idxStr))
		if err != nil {
			return nil, fmt.Errorf("pcr pin %q: index is not a number: %w", p, err)
		}
		if idx < 0 || idx > 23 {
			return nil, fmt.Errorf("pcr pin %q: index must be 0-23", p)
		}
		if _, dup := out[idx]; dup {
			return nil, fmt.Errorf("PCR[%d] pinned more than once", idx)
		}
		v, err := hex.DecodeString(strings.TrimSpace(hexStr))
		if err != nil {
			return nil, fmt.Errorf("pcr pin %d: value is not hex: %w", idx, err)
		}
		if len(v) != PCRDigestSize {
			return nil, fmt.Errorf("pcr pin %d: value is %d bytes, want %d (%d hex characters)", idx, len(v), PCRDigestSize, PCRDigestSize*2)
		}
		out[idx] = v
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ParsePCRPinsString parses a comma-separated list of <index>=<sha256-hex>
// PCR pins (see ParsePCRPins). Empty input returns nil.
func ParsePCRPinsString(raw string) (map[int][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return ParsePCRPins(strings.Split(raw, ","))
}

// ParseInitDataHash parses the hex SHA-256 init-data digest a pin carries.
// Empty input returns nil (no pin).
func ParseInitDataHash(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	v, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("init-data hash is not hex: %w", err)
	}
	if len(v) != PCRDigestSize {
		return nil, fmt.Errorf("init-data hash is %d bytes, want %d (SHA-256 of the init-data document)", len(v), PCRDigestSize)
	}
	return v, nil
}
