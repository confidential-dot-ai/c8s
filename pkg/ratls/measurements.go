package ratls

import (
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Pins is the peer-identity pin set an in-cluster RA-TLS verifier enforces:
// the launch-measurement reference values and, for TDX peers, the runtime
// measurement registers. The zero value pins nothing (accept any attested
// TEE — development only; callers warn).
type Pins struct {
	// Measurements is the set of acceptable launch measurements
	// (VerifyPolicy.Measurements).
	Measurements [][]byte
	// RTMRs pins TDX runtime measurement registers by index
	// (VerifyPolicy.RTMRs). Ignored on SNP evidence, where kernel-hashes
	// folds the guest image into the launch digest.
	RTMRs map[int][]byte

	// ImagePins pins whole images (VerifyPolicy.ImagePins). When set it replaces
	// Measurements and RTMRs, so a digest from one image cannot be paired
	// with another's registers.
	ImagePins []remote.ImagePin
}

// VerifyPolicy converts the pins into the policy the verifying paths read.
// Every caller goes through here: a hand-copied conversion that forgets a
// field drops those pins while still compiling.
func (p Pins) VerifyPolicy(attestationApiURL string) *VerifyPolicy {
	return &VerifyPolicy{
		ImagePins:         p.ImagePins,
		Measurements:      p.Measurements,
		RTMRs:             p.RTMRs,
		AttestationApiURL: attestationApiURL,
	}
}
