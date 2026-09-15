package cmdsutil

import (
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// LoadMeasurementsSource loads a complete policy from a file or inline JSON.
// Inline policies travel with injected sidecars without needing host mounts.
func LoadMeasurementsSource(path, inline string) (refvalues.ReferenceValues, error) {
	if path != "" && inline != "" {
		return refvalues.ReferenceValues{}, fmt.Errorf("--measurements-config cannot be combined with --measurements-config-json")
	}
	if inline != "" {
		set, err := refvalues.Parse([]byte(inline))
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("--measurements-config-json: %w", err)
		}
		return set, nil
	}
	if path != "" {
		return refvalues.Load(path)
	}
	return refvalues.ReferenceValues{}, nil
}
