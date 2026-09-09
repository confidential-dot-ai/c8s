package ratlsmesh

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// resolveMeasurementsConfig loads --measurements-config and fills every flat
// pin field from it: one file lists the images this cluster runs, and both the
// peers this proxy talks to and the CDS it dials are drawn from that one set.
// Filling the flat fields keeps the gates that can only express a digest list
// pinning exactly what they pin today.
func resolveMeasurementsConfig(c *proxyConfig) (refvalues.ReferenceValues, error) {
	if c.measurementsConfig == "" {
		return refvalues.ReferenceValues{}, nil
	}
	for _, f := range []struct{ name, value string }{
		{"--measurements", c.measurements},
		{"--rtmrs", c.rtmrs},
		{"--cds-measurements", c.cdsMeasurements},
		{"--cds-rtmrs", c.cdsRTMRs},
	} {
		if f.value != "" {
			return refvalues.ReferenceValues{}, fmt.Errorf("--measurements-config cannot be combined with %s", f.name)
		}
	}
	set, err := refvalues.Load(c.measurementsConfig)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}

	hexDigests, common, uniform := set.Flatten()
	digests := strings.Join(hexDigests, ",")
	if !uniform {
		// A single register set cannot express per-image tuples; say so
		// rather than appearing to pin them.
		slog.Warn("measurements config pins different registers per image: peers and CDS are matched as whole images, but flags carrying one register set are digest-only",
			"images", len(set.Images))
	}
	joined := make([]string, 0, len(common))
	for _, idx := range sortedRTMRIndices(common) {
		joined = append(joined, fmt.Sprintf("%d=%x", idx, common[idx]))
	}
	pins := strings.Join(joined, ",")

	c.measurements, c.cdsMeasurements = digests, digests
	c.rtmrs, c.cdsRTMRs = pins, pins
	slog.Info("measurements config loaded", "tee", set.Family.String(), "images", len(set.Images))
	return set, nil
}

func sortedRTMRIndices(m map[int][]byte) []int {
	out := make([]int, 0, len(m))
	for i := range m {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

// checkTEEMatchesPlatform reports a config written for the other platform. It
// runs after --platform=auto has probed the guest devices, so the comparison
// is against the platform this proxy actually attests on.
func checkTEEMatchesPlatform(set refvalues.ReferenceValues, teeType ratls.TEEType) error {
	if set.Empty() {
		return nil
	}
	var family teetypes.Family
	switch teeType {
	case ratls.TEETypeSEVSNP:
		family = teetypes.FamilySNP
	case ratls.TEETypeTDX:
		family = teetypes.FamilyTDX
	default:
		return nil
	}
	if set.Family != family {
		return fmt.Errorf("--measurements-config declares tee %q but this node attests as %q", set.Family, family)
	}
	return nil
}
