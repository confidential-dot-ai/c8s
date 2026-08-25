package cds

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// resolveMeasurementsConfig loads --measurements-config and fills the flat
// lists from it, so every gate that can only express a digest list keeps
// pinning exactly what it pins today. The returned reference values carry the
// whole tuples, for the gates that can match them.
func resolveMeasurementsConfig(cfg *config) (measurements.ReferenceValues, error) {
	if cfg.measurementsConfig == "" {
		return measurements.ReferenceValues{}, nil
	}
	if len(cfg.measurements) > 0 || len(cfg.rtmrs) > 0 {
		return measurements.ReferenceValues{}, fmt.Errorf("--measurements-config cannot be combined with --measurements or --rtmrs")
	}
	set, err := measurements.Load(cfg.measurementsConfig)
	if err != nil {
		return measurements.ReferenceValues{}, err
	}
	// Reference values for the other platform would refuse every peer at
	// runtime. An empty platform is validateConfig's error to report.
	if platform := ratls.NormalizePlatform(cfg.ratlsPlatform); platform != "" && platform != set.TEE {
		return measurements.ReferenceValues{}, fmt.Errorf(
			"--measurements-config declares tee %q but --ratls-platform is %q", set.TEE, platform)
	}
	cfg.measurements = set.HexDigests()

	common, uniform := set.CommonRTMRs()
	if !uniform {
		// Gates keyed on a single register set cannot express per-image
		// tuples; say so rather than appearing to pin them.
		slog.Warn("measurements config pins different registers per image: /attest matches whole images, but gates that take one register set (/attest-key) are digest-only",
			"images", len(set.Entries))
	}
	for _, idx := range sortedIndices(common) {
		cfg.rtmrs = append(cfg.rtmrs, fmt.Sprintf("%d=%x", idx, common[idx]))
	}
	if _, err := ratls.ParseRTMRPins(cfg.rtmrs); err != nil {
		return measurements.ReferenceValues{}, fmt.Errorf("--measurements-config: %w", err)
	}
	slog.Info("measurements config loaded", "tee", set.TEE, "images", len(set.Entries))
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
