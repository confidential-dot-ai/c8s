package main

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// installPins resolves the pins install fans into the chart, from either the
// flat flags or a measurements config. In config mode the file travels to the
// components that match whole images, and the same values are also fanned out
// flat so the consumers that read a plain digest list — the NRI plugin, the
// operator's initdata — keep pinning exactly what they pin today.
func installPins() (digests [][]byte, rtmrs map[int][]byte, helmArgs []string, err error) {
	if installMeasurementsConfig == "" {
		digests, err = ratls.ParseHexMeasurementsList(installMeasurements)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("--measurements: %w", err)
		}
		rtmrs, err = ratls.ParseRTMRPins(installRTMRs)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("--rtmrs: %w", err)
		}
		return digests, rtmrs, nil, nil
	}
	if len(installMeasurements) > 0 || len(installRTMRs) > 0 {
		return nil, nil, nil, fmt.Errorf("--measurements-config cannot be combined with --measurements or --rtmrs")
	}

	// helm reads the path itself, so hand it one that does not depend on the
	// working directory the install happened to run from.
	path, err := filepath.Abs(installMeasurementsConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--measurements-config: %w", err)
	}
	set, err := measurements.Load(path)
	if err != nil {
		return nil, nil, nil, err
	}
	common, uniform := set.CommonRTMRs()
	if !uniform {
		// The flat values carry one register set, so images that disagree can
		// only be fanned out as digests.
		slog.Warn("measurements config pins different registers per image: components matching whole images keep them, the flat values are digest-only",
			"images", len(set.Entries))
	}
	// The chart takes the file's content; helm reads the same path this
	// command just validated.
	helmArgs = []string{
		"--set-file", "cds.measurementsConfig=" + path,
		"--set-file", "ratlsMesh.measurementsConfig=" + path,
	}
	return set.Digests(), common, helmArgs, nil
}

// installPinnedMeasurementArgs reports the pins the preflights count, so a
// config satisfies them exactly as the flat flag does.
func installPinnedMeasurementArgs() []string {
	if installMeasurementsConfig != "" {
		return []string{installMeasurementsConfig}
	}
	return installMeasurements
}
