package ratlsmesh

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// resolveMeasurementsConfig loads the config-file pin sources and fills the
// flat fields from them, so gates that can only express a digest list keep
// pinning exactly what they pin today. peer is --measurements-config; cds is
// --cds-measurements-config, falling back to the peer set so a single file
// pins both roles.
func resolveMeasurementsConfig(c *proxyConfig) (peer, cds measurements.ReferenceValues, err error) {
	if c.measurementsConfig == "" && c.cdsMeasurementsConfig == "" {
		return peer, cds, nil
	}
	if c.measurementsConfig != "" {
		flat := []struct{ name, value string }{
			{"--measurements", c.measurements},
			{"--rtmrs", c.rtmrs},
		}
		if c.cdsMeasurementsConfig == "" {
			flat = append(flat,
				struct{ name, value string }{"--cds-measurements", c.cdsMeasurements},
				struct{ name, value string }{"--cds-rtmrs", c.cdsRTMRs},
			)
		}
		for _, f := range flat {
			if f.value != "" {
				return peer, cds, fmt.Errorf("--measurements-config cannot be combined with %s", f.name)
			}
		}
	}
	if c.cdsMeasurementsConfig != "" {
		for _, f := range []struct{ name, value string }{
			{"--cds-measurements", c.cdsMeasurements},
			{"--cds-rtmrs", c.cdsRTMRs},
		} {
			if f.value != "" {
				return peer, cds, fmt.Errorf("--cds-measurements-config cannot be combined with %s", f.name)
			}
		}
	}
	if c.measurementsConfig != "" {
		peer, err = measurements.Load(c.measurementsConfig)
		if err != nil {
			return peer, cds, err
		}
		c.measurements, c.rtmrs = flatPins(peer, "peers")
		slog.Info("measurements config loaded", "tee", peer.TEE, "images", len(peer.Entries))
	}
	switch {
	case c.cdsMeasurementsConfig != "":
		cds, err = measurements.Load(c.cdsMeasurementsConfig)
		if err != nil {
			return peer, cds, err
		}
		if c.measurementsConfig != "" && cds.TEE != peer.TEE {
			return peer, cds, fmt.Errorf("--cds-measurements-config declares tee %q but --measurements-config declares %q", cds.TEE, peer.TEE)
		}
		slog.Info("cds measurements config loaded", "tee", cds.TEE, "images", len(cds.Entries))
	default:
		cds = peer
	}
	c.cdsMeasurements, c.cdsRTMRs = flatPins(cds, "cds")
	return peer, cds, nil
}

// flatPins renders a set into the flat digest-list and register-pin shapes.
func flatPins(set measurements.ReferenceValues, role string) (digests, rtmrPins string) {
	digests = strings.Join(set.HexDigests(), ",")
	common, uniform := set.CommonRTMRs()
	if !uniform {
		// A single register set cannot express per-image tuples; say so
		// rather than appearing to pin them.
		slog.Warn("measurements config pins different registers per image: matched as whole images, but flags carrying one register set are digest-only",
			"role", role, "images", len(set.Entries))
	}
	joined := make([]string, 0, len(common))
	for _, idx := range sortedRTMRIndices(common) {
		joined = append(joined, fmt.Sprintf("%d=%x", idx, common[idx]))
	}
	return digests, strings.Join(joined, ",")
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
func checkTEEMatchesPlatform(set measurements.ReferenceValues, teeType ratls.TEEType) error {
	if set.Empty() {
		return nil
	}
	platform := ""
	switch teeType {
	case ratls.TEETypeSEVSNP:
		platform = measurements.TEESNP
	case ratls.TEETypeTDX:
		platform = measurements.TEETDX
	default:
		return nil
	}
	if set.TEE != platform {
		return fmt.Errorf("--measurements-config declares tee %q but this node attests as %q", set.TEE, platform)
	}
	return nil
}
