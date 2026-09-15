package cmdsutil

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

// LoadMeasurementsSource loads a complete policy from a file or inline JSON.
// Inline policies travel with injected sidecars without needing host mounts.
func LoadMeasurementsSource(path, inline string) (measurements.ReferenceValues, error) {
	if path != "" && inline != "" {
		return measurements.ReferenceValues{}, fmt.Errorf("--measurements-config cannot be combined with --measurements-config-json")
	}
	if inline != "" {
		set, err := measurements.Parse([]byte(inline))
		if err != nil {
			return measurements.ReferenceValues{}, fmt.Errorf("--measurements-config-json: %w", err)
		}
		return set, nil
	}
	if path != "" {
		return measurements.Load(path)
	}
	return measurements.ReferenceValues{}, nil
}
