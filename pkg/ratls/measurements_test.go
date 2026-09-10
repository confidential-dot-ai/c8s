package ratls

import (
	"bytes"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Every verifying path builds its policy from Pins, so a field dropped in the
// conversion would silently unpin without failing to compile.
func TestPinsVerifyPolicyCarriesEveryField(t *testing.T) {
	digest := bytes.Repeat([]byte{0xaa}, SNPMeasurementSize)
	reg := bytes.Repeat([]byte{0xbb}, SNPMeasurementSize)
	pins := Pins{
		Measurements: [][]byte{digest},
		RTMRs:        map[int][]byte{1: reg},
		ImagePins:    []remote.ImagePin{{Name: "image", Digest: digest, RTMRs: map[int][]byte{1: reg}}},
	}

	policy := pins.VerifyPolicy("http://attestation-api")
	if len(policy.ImagePins) != 1 || policy.ImagePins[0].Name != "image" {
		t.Errorf("ImagePins dropped in conversion: %+v", policy.ImagePins)
	}
	if len(policy.Measurements) != 1 || !bytes.Equal(policy.Measurements[0], digest) {
		t.Errorf("Measurements dropped in conversion: %+v", policy.Measurements)
	}
	if !bytes.Equal(policy.RTMRs[1], reg) {
		t.Errorf("RTMRs dropped in conversion: %+v", policy.RTMRs)
	}
	if policy.AttestationApiURL != "http://attestation-api" {
		t.Errorf("AttestationApiURL = %q", policy.AttestationApiURL)
	}
}
