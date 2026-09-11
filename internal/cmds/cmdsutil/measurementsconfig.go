package cmdsutil

import (
	"fmt"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"log/slog"
	"sort"
)

// LoadMeasurementsConfig loads a measurements config and fills the flat flag
// slices from it, so a gate that can only express a digest list keeps pinning
// exactly what it pins today. The returned reference values carry the whole
// tuples, for the gates that can match them.
//
// digests and rtmrs are the command's own flag slices: non-empty means the
// operator set both forms, which is refused rather than merged.
func LoadMeasurementsConfig(path, configFlag, digestFlag, rtmrFlag string, digests, rtmrs *[]string) (refvalues.ReferenceValues, error) {
	if path == "" {
		return refvalues.ReferenceValues{}, nil
	}
	for _, f := range []struct {
		name string
		set  bool
	}{{digestFlag, len(*digests) > 0}, {rtmrFlag, len(*rtmrs) > 0}} {
		if f.set {
			return refvalues.ReferenceValues{}, fmt.Errorf("%s cannot be combined with %s", configFlag, f.name)
		}
	}
	set, err := refvalues.Load(path)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("%s: %w", configFlag, err)
	}

	hexDigests, common, uniform := set.Flatten()
	*digests = hexDigests
	if !uniform {
		// A single register set cannot express per-image tuples; say so
		// rather than appearing to pin them.
		slog.Warn("measurements config pins different registers per image; the flat pins are digest-only",
			"flag", configFlag, "images", len(set.Images))
	}
	pins := make([]string, 0, len(common))
	for _, idx := range sortedIndices(common) {
		pins = append(pins, fmt.Sprintf("%d=%x", idx, common[idx]))
	}
	*rtmrs = pins
	slog.Info("measurements config loaded", "flag", configFlag, "tee", set.Family.String(), "images", len(set.Images))
	return set, nil
}

func sortedIndices(m map[int][]byte) []int {
	out := make([]int, 0, len(m))
	for i := range m {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}
