package getkubeconfig

import (
	"bytes"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"

	"github.com/confidential-dot-ai/c8s/internal/launchdata"
)

// policyFor builds the trust gate from the operator's inputs: the image
// manifest (loaded atomically, its shape naming the platform), the operator
// public key PEM (the exact bytes the initrd hashed, so it must not be
// re-encoded), the digest-pinned workload images the node's measurer is
// expected to have extended, in first-extend order, and — when the node takes
// its deployment config from a launchdata ISO — the staged bundle whose
// commitment replaces the bare operator-key binding. Tag references are
// rejected: only a canonical digest identifies an image.
func policyFor(manifestPath string, operatorPubPEM []byte, workloadImages []string, launchDataDir string) (measuredPolicy, error) {
	identity, err := runtimemeasure.LoadImageManifest(manifestPath)
	if err != nil {
		return measuredPolicy{}, fmt.Errorf("--image-manifest: %w", err)
	}
	if p := identity.Family().DefaultPlatform(); p == "" {
		return measuredPolicy{}, fmt.Errorf("--image-manifest: %s carries an image pin this flow has no gate for (family %q)", manifestPath, identity.Family())
	}
	digests, err := workloadChain(identity.Family(), workloadImages)
	if err != nil {
		return measuredPolicy{}, err
	}
	pol := measuredPolicy{identity: identity, operatorPubPEM: operatorPubPEM, workloadDigests: digests}
	if launchDataDir != "" {
		if pol.launchData, err = launchDataManifest(launchDataDir, operatorPubPEM); err != nil {
			return measuredPolicy{}, err
		}
	}
	return pol, nil
}

// launchDataManifest renders the staged bundle's manifest and requires the
// bundled key bytes to be the public half of --operator-key: the guest takes
// its operator key from the bundle, so one commitment must cover both.
func launchDataManifest(dir string, operatorPubPEM []byte) ([]byte, error) {
	manifest, staged, err := launchdata.LoadLaunchData(dir)
	if err != nil {
		return nil, fmt.Errorf("--launch-data: %w", err)
	}
	if !bytes.Equal(staged, operatorPubPEM) {
		return nil, fmt.Errorf("--launch-data: %s/operator-pubkey is not the public half of --operator-key", dir)
	}
	return manifest, nil
}
