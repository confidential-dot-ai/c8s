//go:build !c8s_node

package main

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// installPins resolves the pins install fans into the chart, from either the
// flat flags or a measurements config. In config mode the file travels to the
// components that match whole images, and the same values are also fanned out
// flat for consumers that read a plain digest list, such as the NRI plugin.
func installPins() (digests [][]byte, rtmrs map[int][]byte, helmArgs []string, err error) {
	source := cmdsutil.ImagePolicySource{File: installMeasurementsConfig}
	legacy := cmdsutil.LegacyPins{Measurements: installMeasurements, RTMRs: installRTMRs}
	if !source.Set() {
		policy, err := source.Load(legacy)
		return policy.Measurements, policy.RTMRs, nil, err
	}
	set, err := source.LoadValues(legacy)
	if err != nil {
		return nil, nil, nil, err
	}

	// helm reads the path itself, so hand it one that does not depend on the
	// working directory the install happened to run from.
	path, err := filepath.Abs(installMeasurementsConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--image-policy-file: %w", err)
	}
	if set.HasAnchors() {
		return nil, nil, nil, fmt.Errorf("approver_key policies require the baked node launch flow; Helm installation cannot carry them to every NRI verifier")
	}
	common, uniform := set.CommonRTMRs()
	if !uniform {
		// The flat values carry one register set, so images that disagree can
		// only be fanned out as digests.
		slog.Warn("measurements config pins different registers per image: components matching whole images keep them, the flat values are digest-only",
			"images", len(set.Images))
	}
	// The chart takes the file's content; helm reads the same path this
	// command just validated.
	helmArgs = []string{
		"--set-file", "cds.measurementsConfig=" + path,
		"--set-file", "ratlsMesh.measurementsConfig=" + path,
	}
	return set.Digests(), common, helmArgs, nil
}
