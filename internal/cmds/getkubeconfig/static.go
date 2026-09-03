package getkubeconfig

import (
	"context"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// staticRTMR3Meaning names the chain a static node's register pins.
const staticRTMR3Meaning = "static mode event + policy bundle index"

// staticPolicy pins the image tuple and the static register: a node sealed
// to the bundle extended the static mode event and then the bundle index,
// and nothing after. There is no operator key and no workload chain.
func staticPolicy(pins runtimemeasure.ImagePins, rtmr3 [runtimemeasure.Size]byte) measuredPolicy {
	return measuredPolicy{
		platform:     teetypes.PlatformTDX,
		pins:         pins,
		rtmr3:        rtmr3,
		chainMeaning: staticRTMR3Meaning,
	}
}

// policyForStatic builds the trust gate for a static node from the TDX image
// manifest and the bundle it booted with. The bundle's static-allowlist.json
// is linted first (allowlist.LintSealed): the node refused to boot anything
// unsealed, so a bundle that fails here can only be the wrong file.
func policyForStatic(manifestPath, bundlePath string) (measuredPolicy, error) {
	pins, err := runtimemeasure.LoadImageManifest(manifestPath)
	if err != nil {
		return measuredPolicy{}, fmt.Errorf("--image-manifest: %w (a static allowlist needs a TDX manifest: only TDX has the register the policy is measured into)", err)
	}
	bundle, err := policybundle.Load(bundlePath)
	if err != nil {
		return measuredPolicy{}, fmt.Errorf("--static-allowlist: %w", err)
	}
	if err := allowlist.LintSealed(bundle.Members[policybundle.MemberStaticAllowlist]); err != nil {
		return measuredPolicy{}, fmt.Errorf("--static-allowlist %s: %w", policybundle.MemberStaticAllowlist, err)
	}
	return staticPolicy(pins, bundle.RTMR3()), nil
}

// VerifyStaticNode attests the node behind attestURL and requires the static
// tuple: the manifest's image registers and RTMR[3] equal to rtmr3, the
// register a node sealed to the expected bundle reports. It is the gate
// `c8s install --static-allowlist` runs against every node before rendering
// the chart, and the same gate get-kubeconfig runs before releasing a
// credential.
func VerifyStaticNode(ctx context.Context, attestURL string, pins runtimemeasure.ImagePins, rtmr3 [runtimemeasure.Size]byte) error {
	return attestAndVerify(ctx, attestURL, staticPolicy(pins, rtmr3))
}
