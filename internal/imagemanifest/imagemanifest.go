// Package imagemanifest reads the reference TDX registers a confos build
// manifest publishes for a guest image, so every verifier pins the same three
// values from the same provenanced source.
//
// On TDX the launch measurement (MRTD) covers the TDVF firmware's measured
// regions and NOTHING ELSE: two entirely different guest images built against
// the same firmware share an MRTD. Which kernel and rootfs booted lives in
// RTMR[1] and RTMR[2]. Pinning them from one manifest is what keeps the three
// from drifting apart — a verifier that pins MRTD alone has not pinned the
// image.
package imagemanifest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// Pins are the reference registers for one guest image.
type Pins struct {
	MRTD  []byte
	RTMR1 []byte
	RTMR2 []byte
}

// manifest is the subset of a confos build manifest.json that carries them.
type manifest struct {
	TDX struct {
		MRTD  string `json:"mrtd"`
		RTMR1 string `json:"rtmr1"`
		RTMR2 string `json:"rtmr2"`
	} `json:"tdx"`
}

// Load reads a confos manifest.json and returns its TDX pins. flag names the
// CLI flag the path came from, so errors read as the caller's own invocation.
// A manifest missing any of the three is refused rather than yielding a
// partial pin: pinning two registers reports the same verdict shape as pinning
// three while proving materially less.
func Load(flag, path string) (Pins, error) {
	var p Pins
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read %s: %w", flag, err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return p, fmt.Errorf("%s: not a confos manifest.json: %w", flag, err)
	}
	if m.TDX.MRTD == "" || m.TDX.RTMR1 == "" || m.TDX.RTMR2 == "" {
		return p, fmt.Errorf("%s: missing tdx.mrtd/tdx.rtmr1/tdx.rtmr2 (is this a TDX image manifest?)", flag)
	}
	if p.MRTD, err = ParseRegister(flag+" tdx.mrtd", m.TDX.MRTD); err != nil {
		return Pins{}, err
	}
	if p.RTMR1, err = ParseRegister(flag+" tdx.rtmr1", m.TDX.RTMR1); err != nil {
		return Pins{}, err
	}
	if p.RTMR2, err = ParseRegister(flag+" tdx.rtmr2", m.TDX.RTMR2); err != nil {
		return Pins{}, err
	}
	return p, nil
}

// ParseRegister decodes one measurement register value: SHA-384 as hex. flag
// names the source for the error message.
func ParseRegister(flag, s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %w", flag, err)
	}
	if len(b) != runtimemeasure.Size {
		return nil, fmt.Errorf("%s is %d bytes (%d hex chars), want %d (%d hex chars)",
			flag, len(b), len(strings.TrimSpace(s)), runtimemeasure.Size, runtimemeasure.Size*2)
	}
	return b, nil
}
