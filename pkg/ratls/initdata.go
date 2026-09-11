package ratls

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Init-data widths: SNP HOST_DATA is 32 bytes, TDX MRCONFIGID 48.
const (
	SNPHostDataSize   = 32
	TDXMRConfigIDSize = 48
)

// ParseHexInitData parses a hex-encoded launch-time init-data value (SNP
// HOST_DATA or TDX MRCONFIGID) into the byte form
// [Pins.ExpectedInitDataHash] takes. Blank input returns nil, which pins
// nothing.
func ParseHexInitData(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid hex init-data %q: %w", raw, err)
	}
	if len(decoded) != SNPHostDataSize && len(decoded) != TDXMRConfigIDSize {
		return nil, fmt.Errorf("init-data %q is %d bytes, want %d (SNP HOST_DATA) or %d (TDX MRCONFIGID)",
			raw, len(decoded), SNPHostDataSize, TDXMRConfigIDSize)
	}
	return decoded, nil
}
