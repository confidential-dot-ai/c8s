package getkubeconfig

import (
	"bytes"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/launchdata"
)

// policyFor loads the image and optional launchdata bundle, then constructs
// the platform policy from the operator key and ordered workload references.
func policyFor(manifestPath string, operatorPubPEM []byte, workloadImages []string, launchDataDir string) (measuredPolicy, error) {
	var seeds *bindingSeeds
	if launchDataDir != "" {
		var err error
		if seeds, err = launchDataSeeds(launchDataDir, operatorPubPEM); err != nil {
			return nil, err
		}
	}
	// The manifest's shape names the platform: a TDX build publishes the
	// mrtd/rtmr1/rtmr2 tuple, an SNP build publishes snp_variants (per-SMP
	// launch digests). TDX is tried first so a manifest that is neither keeps
	// the TDX error text.
	pins, tdxErr := runtimemeasure.LoadImageManifest(manifestPath)
	if tdxErr == nil {
		return tdxPolicy(pins, operatorPubPEM, workloadImages, seeds)
	}
	snpPins, snpErr := runtimemeasure.LoadSNPImageManifest(manifestPath)
	if snpErr != nil {
		return nil, fmt.Errorf("--image-manifest: %w", tdxErr)
	}
	return snpPolicy(snpPins, operatorPubPEM, workloadImages, seeds)
}

// bindingSeeds carries the launchdata-derived binding expectations.
type bindingSeeds struct {
	hostData   [runtimemeasure.HostDataSize]byte
	mrconfigID [runtimemeasure.Size]byte
}

// launchDataSeeds requires the bundled key bytes to match the operator's public key.
func launchDataSeeds(dir string, operatorPubPEM []byte) (*bindingSeeds, error) {
	manifest, staged, err := launchdata.LoadLaunchData(dir)
	if err != nil {
		return nil, fmt.Errorf("--launch-data: %w", err)
	}
	if !bytes.Equal(staged, operatorPubPEM) {
		return nil, fmt.Errorf("--launch-data: %s/operator-pubkey is not the public half of --operator-key", dir)
	}
	return &bindingSeeds{
		hostData:   launchdata.LaunchDataHostData(manifest),
		mrconfigID: launchdata.LaunchDataMRConfigID(manifest),
	}, nil
}
