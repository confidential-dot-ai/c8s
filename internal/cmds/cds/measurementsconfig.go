package cds

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// resolveMeasurementsConfig loads --measurements-config and fills the flat
// lists from it, so every gate that can only express a digest list keeps
// pinning exactly what it pins today. The returned reference values carry the
// whole tuples, for the gates that can match them.
func resolveMeasurementsConfig(cfg *config) (refvalues.ReferenceValues, error) {
	if cfg.measurementsConfig == "" {
		return refvalues.ReferenceValues{}, nil
	}
	if len(cfg.measurements) > 0 || len(cfg.rtmrs) > 0 {
		return refvalues.ReferenceValues{}, fmt.Errorf("--measurements-config cannot be combined with --measurements or --rtmrs")
	}
	set, err := refvalues.Load(cfg.measurementsConfig)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	// Reference values for the other platform would refuse every peer at
	// runtime. An empty platform is validateConfig's error to report.
	if family, err := teetypes.ParseFamily(cfg.ratlsPlatform); err == nil && family != set.Family {
		return refvalues.ReferenceValues{}, fmt.Errorf(
			"--measurements-config declares tee %q but --ratls-platform is %q", set.Family, family)
	}

	hexDigests, common, uniform := set.Flatten()
	cfg.measurements = hexDigests
	if !uniform {
		// Gates keyed on a single register set cannot express per-image
		// tuples; say so rather than appearing to pin them.
		slog.Warn("measurements config pins different registers per image: /attest matches whole images, but gates that take one register set (/attest-key) are digest-only",
			"images", len(set.Images))
	}
	for _, idx := range sortedIndices(common) {
		cfg.rtmrs = append(cfg.rtmrs, fmt.Sprintf("%d=%x", idx, common[idx]))
	}
	if _, err := refvalues.ParseRTMRPins(cfg.rtmrs); err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("--measurements-config: %w", err)
	}
	slog.Info("measurements config loaded", "tee", set.Family.String(), "images", len(set.Images))
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

// servedFamily names the platform the served document declares. The flat flags
// carry no platform of their own, so it comes from the one CDS attests on.
func servedFamily(ratlsPlatform string) teetypes.Family {
	if fam, err := teetypes.ParseFamily(ratlsPlatform); err == nil {
		return fam
	}
	return teetypes.FamilySNP
}

// measurementBytes decodes the flat allowlist back into digests for the
// served document. Entries that are not hex never reached a gate either.
func measurementBytes(allowed map[string]bool) [][]byte {
	out := make([][]byte, 0, len(allowed))
	for m := range allowed {
		if b, err := hex.DecodeString(m); err == nil {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}
