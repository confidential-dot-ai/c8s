package measurements

import (
	"errors"
	"fmt"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// ErrOperatorKeyNotAllowed means evidence did not bind its image's operator.
var ErrOperatorKeyNotAllowed = errors.New("measurements: operator key not allowed")

// EnforceEntries checks each image and its operator against the same verified
// response. Callers must first verify the hardware signature and REPORTDATA.
// Generic image matching stays in remote.EnforceImages, including refusing
// register pins when evidence comes from a platform without registers.
func EnforceEntries(resp remote.VerifyResponse, entries []Entry, platform string) error {
	if len(entries) == 0 {
		return nil
	}
	platformType := teetypes.NormalizePlatform(platform)
	var lastErr error
	for _, e := range entries {
		if err := remote.EnforceImages(resp, []remote.ImagePin{e.image()}, platformType); err != nil {
			if lastErr == nil || !errors.Is(err, remote.ErrMeasurementNotAllowed) {
				lastErr = err
			}
			continue
		}
		if len(e.OperatorKey) > 0 {
			if platformType != teetypes.NormalizePlatform(string(resp.Result.Platform)) {
				lastErr = fmt.Errorf("%s: %w: verified platform does not match evidence", e.Name, ErrOperatorKeyNotAllowed)
				continue
			}
			if err := runtimemeasure.VerifyBinding(&resp.Result, e.OperatorKey, nil); err != nil {
				lastErr = fmt.Errorf("%s: %w: %w", e.Name, ErrOperatorKeyNotAllowed, err)
				continue
			}
		}
		return nil
	}
	return lastErr
}
