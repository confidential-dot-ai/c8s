package measurements_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

const (
	digestA = "aa11" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	digestB = "bb22" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	regA1   = "1111" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evidence(t *testing.T, digest string, rtmrs map[string]string) remote.VerifyResponse {
	t.Helper()
	var resp remote.VerifyResponse
	resp.Result.Claims.LaunchDigest = digest
	if rtmrs != nil {
		pd := make(map[string]any, len(rtmrs))
		for k, v := range rtmrs {
			pd[k] = v
		}
		resp.Result.Claims.PlatformData = pd
	}
	return resp
}

func entryTDX(t *testing.T, name, digest string, r1, r2 string) measurements.Entry {
	t.Helper()
	e := measurements.Entry{Name: name, Digest: mustHex(t, digest), RTMRs: map[int][]byte{}}
	if r1 != "" {
		e.RTMRs[1] = mustHex(t, r1)
	}
	if r2 != "" {
		e.RTMRs[2] = mustHex(t, r2)
	}
	return e
}

// A follower on the same image must never satisfy the leader-only CDS policy.
func TestEnforceEntriesPinsOperatorWithImage(t *testing.T) {
	leader := []byte("leader launch key")
	follower := []byte("follower launch key")
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformTDX} {
		t.Run(string(platform), func(t *testing.T) {
			bound := func(digest string, key []byte) remote.VerifyResponse {
				r := evidence(t, digest, map[string]string{"rtmr_1": regA1})
				r.Result.SignatureValid = true
				r.Result.Platform = platform
				if platform == teetypes.PlatformTDX {
					seed := runtimemeasure.Seed(key)
					r.Result.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seed[:])
				} else {
					hostData := runtimemeasure.HostData(key)
					r.Result.Claims.InitData = hostData[:]
				}
				return r
			}
			entry := entryTDX(t, "leader", digestA, regA1, "")
			entry.OperatorKey = leader
			if platform == teetypes.PlatformSNP {
				entry.RTMRs = nil
			}
			policy := []measurements.Entry{entry}
			if err := measurements.EnforceEntries(bound(digestA, leader), policy, string(platform)); err != nil {
				t.Fatalf("leader refused: %v", err)
			}
			if err := measurements.EnforceEntries(bound(digestA, follower), policy, string(platform)); !errors.Is(err, measurements.ErrOperatorKeyNotAllowed) {
				t.Fatalf("follower with same image: %v", err)
			}
			missing := bound(digestA, leader)
			missing.Result.Claims.InitData = nil
			delete(missing.Result.Claims.PlatformData, "rtmr_3")
			if err := measurements.EnforceEntries(missing, policy, string(platform)); !errors.Is(err, measurements.ErrOperatorKeyNotAllowed) {
				t.Fatalf("missing operator binding: %v", err)
			}
			unverified := bound(digestA, leader)
			unverified.Result.SignatureValid = false
			if err := measurements.EnforceEntries(unverified, policy, string(platform)); !errors.Is(err, measurements.ErrOperatorKeyNotAllowed) {
				t.Fatalf("unverified claims accepted: %v", err)
			}
			if err := measurements.EnforceEntries(bound(digestA, leader), policy, "different-platform"); err == nil {
				t.Fatalf("inconsistent verified platform accepted: %v", err)
			}
			// Neither key matching a different image nor the shared image
			// matching a different role may satisfy half of a tuple.
			other := entry
			other.Name, other.Digest, other.OperatorKey = "other", mustHex(t, digestB), follower
			if err := measurements.EnforceEntries(bound(digestA, follower), append(policy, other), string(platform)); err == nil {
				t.Fatal("crossed image/operator tuple accepted")
			}
			// Mesh may explicitly allow both roles on the same image.
			other.Digest = entry.Digest
			if err := measurements.EnforceEntries(bound(digestA, follower), append(policy, other), string(platform)); err != nil {
				t.Fatalf("authorized follower refused: %v", err)
			}
		})
	}
}
