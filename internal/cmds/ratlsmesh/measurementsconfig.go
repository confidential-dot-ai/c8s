//go:build linux

package ratlsmesh

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// resolveMeasurementsConfig loads whole peer identities. Without a separate
// CDS config the legacy behavior accepts the same set for both purposes.
func resolveMeasurementsConfig(c *proxyConfig) (measurements.ReferenceValues, error) {
	if c.measurementsConfig == "" && c.cdsMeasurementsConfig == "" {
		return measurements.ReferenceValues{}, nil
	}
	if c.measurementsConfig != "" && (c.measurements != "" || c.rtmrs != "") {
		return measurements.ReferenceValues{}, fmt.Errorf("--measurements-config cannot be combined with --measurements or --rtmrs")
	}
	if c.cdsMeasurements != "" || c.cdsRTMRs != "" {
		return measurements.ReferenceValues{}, fmt.Errorf("measurements configs cannot be combined with --cds-measurements or --cds-rtmrs")
	}
	var peers measurements.ReferenceValues
	if c.measurementsConfig != "" {
		var err error
		peers, err = measurements.Load(c.measurementsConfig)
		if err != nil {
			return measurements.ReferenceValues{}, err
		}
	}
	cds := peers
	if c.cdsMeasurementsConfig != "" {
		var err error
		cds, err = measurements.Load(c.cdsMeasurementsConfig)
		if err != nil {
			return measurements.ReferenceValues{}, fmt.Errorf("--cds-measurements-config: %w", err)
		}
		if !peers.Empty() && peers.TEE != cds.TEE {
			return measurements.ReferenceValues{}, fmt.Errorf("peer and CDS measurements configs declare different TEEs")
		}
	}
	if !peers.Empty() {
		c.measurements, c.rtmrs = flatPins(peers)
	}
	c.cdsMeasurements, c.cdsRTMRs = flatPins(cds)
	c.cdsPins = cds
	slog.Info("measurements configs loaded", "peer_identities", len(peers.Entries), "cds_identities", len(cds.Entries))
	return peers, nil
}

// flatPins fills legacy diagnostics; verification always keeps the entries.
func flatPins(set measurements.ReferenceValues) (string, string) {
	common, _ := set.CommonRTMRs()
	return strings.Join(set.HexDigests(), ","), strings.Join(measurements.FormatRTMRPins(common), ",")
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
