package attestationclient

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// EnforceEntries accepts evidence matching one reference image whole: its
// launch digest AND, on TDX, every register that image pins. A digest from one
// build with registers from another matches nothing, which is what pinning the
// two separately could not express.
//
// RTMRs are checked only for TDX-shaped evidence, as elsewhere: SNP folds the
// guest image into its launch digest and reports no registers.
func EnforceEntries(resp types.VerifyResponse, entries []measurements.Entry, platform string) error {
	if len(entries) == 0 {
		return nil
	}
	digest, err := launchDigest(resp)
	if err != nil {
		return err
	}

	var reported [4]string
	checkRTMRs := TDXPlatform(platform)
	if checkRTMRs {
		if reported, err = reportedRTMRs(resp); err != nil {
			return err
		}
	}

	var lastErr error
	for _, e := range entries {
		if !bytes.Equal(digest, e.Digest) {
			continue
		}
		if !checkRTMRs || len(e.RTMRs) == 0 {
			return nil
		}
		if err := enforceRTMRsAgainst(reported, e.RTMRs); err != nil {
			lastErr = fmt.Errorf("%s: %w", e.Name, err)
			continue
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: no pinned image has this launch measurement", ErrMeasurementNotAllowed)
}

// launchDigest validates the reported digest. A missing digest is a refusal:
// entries always pin, so there is nothing it could legitimately match.
func launchDigest(resp types.VerifyResponse) ([]byte, error) {
	raw := strings.ToLower(strings.TrimSpace(resp.Result.Claims.LaunchDigest))
	if raw == "" {
		return nil, fmt.Errorf("%w: launch measurement missing", ErrMeasurementNotAllowed)
	}
	digest, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: launch digest is not hex: %w", ErrInvalidLaunchDigest, err)
	}
	if len(digest) != launchMeasurementSize {
		return nil, fmt.Errorf("%w: launch digest is %d bytes, expected %d", ErrInvalidLaunchDigest, len(digest), launchMeasurementSize)
	}
	return digest, nil
}
