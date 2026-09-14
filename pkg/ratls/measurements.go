package ratls

import (
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

// Pins carries shared image pins and optional c8s launch-bound node identities.
// Entries replace the image pins; the complete tuple is enforced on one response.
type Pins struct {
	Measurements [][]byte
	RTMRs        map[int][]byte
	Images       []remote.ImagePin
	Entries      []measurements.Entry
}

// VerifyPolicy is the single conversion used by c8s peer verifiers.
func (p Pins) VerifyPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{
		Policy:            remote.Policy{Measurements: p.Measurements, RTMRs: p.RTMRs, Images: p.Images},
		Entries:           p.Entries,
		AttestationApiURL: url,
	}
}
