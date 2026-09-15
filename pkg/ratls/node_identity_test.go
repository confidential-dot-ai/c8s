package ratls

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

// The policy must survive Pins conversion and the complete certificate
// verification path, not just the standalone claims checker.
func TestVerifyCertRequiresLeaderLaunchKey(t *testing.T) {
	_, att, cert := testAttestedCert(t, nil)
	digest := att.Report[0x90:0xc0]
	leader, follower := []byte("leader key"), []byte("follower key")
	stub := mockapi.New(t)
	policy := Pins{Entries: []measurements.Entry{{Name: "leader", Digest: digest, OperatorKey: leader}}}.VerifyPolicy(stub.URL())
	for _, tc := range []struct {
		name   string
		key    []byte
		accept bool
	}{
		{"leader", leader, true}, {"follower same image", follower, false}, {"missing binding", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := mockapi.PassingVerdict(hex.EncodeToString(digest))
			if tc.key != nil {
				binding := runtimemeasure.HostData(tc.key)
				verdict.Claims.InitData = binding[:]
			}
			stub.SetVerdict(verdict)
			_, err := VerifyCert(cert, policy, nil)
			if tc.accept && err != nil {
				t.Fatalf("leader rejected: %v", err)
			}
			if !tc.accept && !errors.Is(err, ErrPolicyViolation) {
				t.Fatalf("unauthorized node accepted: %v", err)
			}
		})
	}
}
