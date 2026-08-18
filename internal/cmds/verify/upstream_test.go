package verify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

// upstreamOutcome builds a passing SNP verdict for endpoint-style evidence
// with the SAME plan threaded through outcome construction and policies (as
// verifyEvidence does), so applyUpstreamPolicy sees the --mesh-ca hash.
func upstreamOutcome(t *testing.T, cfg config, meshCAHash []byte, upstream overenc.UpstreamIdentity) Outcome {
	t.Helper()
	launch := "ab" + strings.Repeat("00", 47)
	if cfg.measurements == nil {
		cfg.measurements = []string{launch}
	}
	plan := mustPlan(t, cfg)
	plan.meshCAHash = meshCAHash
	ev := &evidence{
		platform:      "snp",
		source:        "attestation endpoint https://lb.example.com/.well-known/c8s/attest-pq",
		bindingNote:   "REPORTDATA binds the identity transcript",
		upstream:      upstream,
		upstreamBound: true,
	}
	result := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: launch},
	}
	oc := newOutcome(cfg, ev, result, nil, plan)
	applyVerdictPolicies(&oc, cfg, plan, ev, nil, operatorKeysReport{})
	return oc
}

// The committed upstream is hardware-bound but only meaningful against an
// operator pin: a mismatch is fatal, no pin is partial, and an https
// upstream's CA bundle is proven only against the pinned --mesh-ca bundle.
func TestApplyUpstreamPolicy(t *testing.T) {
	committed := overenc.UpstreamIdentity{URL: "http://c8s-infer.c8s-system.svc.cluster.local:8000"}

	t.Run("pin match verifies", func(t *testing.T) {
		oc := upstreamOutcome(t, config{expectedUpstream: committed.URL}, nil, committed)
		if !oc.Verified || oc.Partial {
			t.Fatalf("verified=%v partial=%v, want a clean verdict", oc.Verified, oc.Partial)
		}
		if oc.Upstream != committed.URL || !strings.Contains(oc.UpstreamNote, "matches --expected-upstream") {
			t.Errorf("upstream = %q note = %q", oc.Upstream, oc.UpstreamNote)
		}
		if got := verdictExitCode(oc); got != exitVerified {
			t.Errorf("exit = %d, want %d", got, exitVerified)
		}
	})

	t.Run("pin mismatch fails", func(t *testing.T) {
		oc := upstreamOutcome(t, config{expectedUpstream: "http://c8s-other.c8s-system.svc.cluster.local:8000"}, nil, committed)
		if oc.Verified || oc.Partial || oc.Error == "" {
			t.Fatalf("verified=%v partial=%v error=%q, want a failure", oc.Verified, oc.Partial, oc.Error)
		}
		if !strings.Contains(oc.Error, "upstream destination mismatch") ||
			!strings.Contains(oc.Error, committed.URL) {
			t.Errorf("error = %q, want it to name the committed and pinned destinations", oc.Error)
		}
		if got := verdictExitCode(oc); got != exitFailed {
			t.Errorf("exit = %d, want %d", got, exitFailed)
		}
	})

	t.Run("no pin is partial", func(t *testing.T) {
		oc := upstreamOutcome(t, config{}, nil, committed)
		if oc.Verified || !oc.Partial {
			t.Fatalf("verified=%v partial=%v, want a partial verdict", oc.Verified, oc.Partial)
		}
		if len(oc.NotProven) != 1 || !strings.Contains(oc.NotProven[0], "upstream destination") ||
			!strings.Contains(oc.NotProven[0], committed.URL) {
			t.Errorf("NotProven = %v, want it to name the committed destination", oc.NotProven)
		}
		if got := verdictExitCode(oc); got != exitPartial {
			t.Errorf("exit = %d, want %d", got, exitPartial)
		}
	})

	t.Run("no pin and nothing committed verifies", func(t *testing.T) {
		oc := upstreamOutcome(t, config{}, nil, overenc.UpstreamIdentity{})
		if !oc.Verified || oc.Partial {
			t.Fatalf("verified=%v partial=%v, want a clean verdict for the echo shape", oc.Verified, oc.Partial)
		}
		if oc.Upstream != "" {
			t.Errorf("upstream = %q, want empty", oc.Upstream)
		}
	})

	t.Run("https upstream CA authenticated by --mesh-ca", func(t *testing.T) {
		caHash := bytes.Repeat([]byte{0x5a}, 32)
		https := overenc.UpstreamIdentity{URL: "https://backend.other.svc:8443", ServerName: "backend.other.svc", CAHash: caHash}
		oc := upstreamOutcome(t, config{expectedUpstream: https.URL}, caHash, https)
		if !oc.Verified || oc.Partial {
			t.Fatalf("verified=%v partial=%v, want a clean verdict", oc.Verified, oc.Partial)
		}
		if !strings.Contains(oc.UpstreamNote, "--mesh-ca") {
			t.Errorf("UpstreamNote = %q, want it to credit the --mesh-ca match", oc.UpstreamNote)
		}
	})

	t.Run("https upstream CA not the pinned bundle is partial", func(t *testing.T) {
		caHash := bytes.Repeat([]byte{0x5a}, 32)
		https := overenc.UpstreamIdentity{URL: "https://backend.other.svc:8443", ServerName: "backend.other.svc", CAHash: caHash}
		for _, tc := range []struct {
			name       string
			meshCAHash []byte
		}{
			{"mesh-ca unset", nil},
			{"different bundle", bytes.Repeat([]byte{0xa5}, 32)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				oc := upstreamOutcome(t, config{expectedUpstream: https.URL}, tc.meshCAHash, https)
				if oc.Verified || !oc.Partial {
					t.Fatalf("verified=%v partial=%v, want a partial verdict", oc.Verified, oc.Partial)
				}
				if len(oc.NotProven) != 1 || !strings.Contains(oc.NotProven[0], "trust root") {
					t.Errorf("NotProven = %v, want it to name the upstream TLS trust root", oc.NotProven)
				}
			})
		}
	})

	t.Run("non-endpoint evidence is untouched", func(t *testing.T) {
		ev := &evidence{platform: "snp", source: "test", bindingNote: "b"}
		plan := mustPlan(t, config{measurements: []string{"ab" + strings.Repeat("00", 47)}})
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims:         teetypes.Claims{LaunchDigest: "ab" + strings.Repeat("00", 47)},
		}
		oc := newOutcome(config{}, ev, result, nil, plan)
		applyVerdictPolicies(&oc, config{}, plan, ev, nil, operatorKeysReport{})
		if !oc.Verified || oc.Upstream != "" {
			t.Fatalf("verified=%v upstream=%q, want the policy to skip non-endpoint evidence", oc.Verified, oc.Upstream)
		}
	})
}
