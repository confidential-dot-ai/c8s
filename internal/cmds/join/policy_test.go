package join

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func writeNodePolicy(t *testing.T, file nodePolicyFile) string {
	t.Helper()
	b, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node-policy.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Test policy files are in a temporary writable directory. The production
// loader checks the mount before it reads the file; this helper isolates policy
// parsing/verification tests from that OS-level invariant.
func loadTestNodePolicy(t *testing.T, path string) (*nodePolicyRegistry, error) {
	t.Helper()
	old := policyFileReadOnly
	policyFileReadOnly = func(string) error { return nil }
	t.Cleanup(func() { policyFileReadOnly = old })
	return loadNodePolicyFile(path)
}

func mixedNodePolicy() nodePolicyFile {
	return nodePolicyFile{
		Version: nodePolicyFileVersion,
		Platforms: []nodePlatformPolicy{
			{Platform: "snp", Measurements: []string{digestA}, AllowPeers: []string{"tdx"}, MinTCB: &types.MinTcb{Snp: 1, Microcode: 2}},
			{Platform: "tdx", Measurements: []string{digestB}, AllowPeers: []string{"snp"}, TDX: &tdxPolicy{Profiles: []tdxProfile{{RTMR1: rtmr1A, RTMR2: rtmr2A}}}},
		},
	}
}

func TestLoadNodePolicyFile(t *testing.T) {
	t.Run("compiles native SNP and TDX policies", func(t *testing.T) {
		r, err := loadTestNodePolicy(t, writeNodePolicy(t, mixedNodePolicy()))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.byPlatform) != 2 || len(r.byPlatform[string(types.PlatformSnp)].measurements) != 1 || len(r.byPlatform[string(types.PlatformTdx)].tdxProfiles) != 1 {
			t.Fatalf("registry = %#v", r)
		}
	})

	for _, tc := range []struct {
		name string
		mut  func(*nodePolicyFile)
	}{
		{"unknown version", func(p *nodePolicyFile) { p.Version++ }},
		{"no platforms", func(p *nodePolicyFile) { p.Platforms = nil }},
		{"unsupported platform", func(p *nodePolicyFile) { p.Platforms[0].Platform = "az-snp" }},
		{"duplicate platform", func(p *nodePolicyFile) { p.Platforms[1].Platform = "sev-snp" }},
		{"missing measurement", func(p *nodePolicyFile) { p.Platforms[0].Measurements = nil }},
		{"missing peer permission", func(p *nodePolicyFile) { p.Platforms[0].AllowPeers = nil }},
		{"duplicate peer permission", func(p *nodePolicyFile) { p.Platforms[0].AllowPeers = []string{"tdx", "tdx"} }},
		{"unregistered peer permission", func(p *nodePolicyFile) { p.Platforms = p.Platforms[1:] }},
		{"short measurement", func(p *nodePolicyFile) { p.Platforms[0].Measurements[0] = "aa" }},
		{"duplicate measurement", func(p *nodePolicyFile) { p.Platforms[0].Measurements = []string{digestA, digestA} }},
		{"TDX minimum TCB is unsupported", func(p *nodePolicyFile) { p.Platforms[1].MinTCB = &types.MinTcb{Microcode: 1} }},
		{"SNP TDX constraints", func(p *nodePolicyFile) {
			p.Platforms[0].TDX = &tdxPolicy{Profiles: []tdxProfile{{RTMR1: rtmr1A, RTMR2: rtmr2A}}}
		}},
		{"empty TDX profiles", func(p *nodePolicyFile) { p.Platforms[1].TDX.Profiles = nil }},
		{"incomplete TDX constraint", func(p *nodePolicyFile) { p.Platforms[1].TDX.Profiles[0].RTMR2 = "" }},
		{"duplicate TDX profile", func(p *nodePolicyFile) {
			p.Platforms[1].TDX.Profiles = append(p.Platforms[1].TDX.Profiles, p.Platforms[1].TDX.Profiles[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mixedNodePolicy()
			tc.mut(&p)
			if _, err := loadTestNodePolicy(t, writeNodePolicy(t, p)); err == nil {
				t.Fatal("expected invalid policy to fail")
			}
		})
	}
}

func TestNodePolicyHelpersFailClosed(t *testing.T) {
	r, err := loadTestNodePolicy(t, writeNodePolicy(t, mixedNodePolicy()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.policyForEvidence("azure-snp"); err == nil {
		t.Fatal("unsupported evidence platform selected a policy")
	}
	if _, err := (&nodePolicyRegistry{byPlatform: map[string]compiledNodePolicy{}}).policyForEvidence("snp"); err == nil {
		t.Fatal("unregistered evidence platform selected a policy")
	}

	tdx := r.byPlatform[string(types.PlatformTdx)]
	for _, tc := range []struct {
		name   string
		claims types.Claims
		wantOK bool
	}{
		{"matching profile", types.Claims{PlatformData: json.RawMessage(`{"rtmr_1":"` + rtmr1A + `","rtmr_2":"` + rtmr2A + `"}`)}, true},
		{"invalid platform data", types.Claims{PlatformData: json.RawMessage(`not-json`)}, false},
		{"invalid RTMR", types.Claims{PlatformData: json.RawMessage(`{"rtmr_1":"bad","rtmr_2":"` + rtmr2A + `"}`)}, false},
		{"unapproved pair", types.Claims{PlatformData: json.RawMessage(`{"rtmr_1":"` + rtmr1B + `","rtmr_2":"` + rtmr2A + `"}`)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tdx.enforceClaims(tc.claims)
			if (err == nil) != tc.wantOK {
				t.Fatalf("enforceClaims() error = %v, wantOK=%v", err, tc.wantOK)
			}
		})
	}
	if err := r.byPlatform[string(types.PlatformSnp)].enforceClaims(types.Claims{}); err != nil {
		t.Fatalf("SNP policy unexpectedly enforced TDX RTMR claims: %v", err)
	}
	if err := (compiledNodePolicy{platform: string(types.PlatformTdx)}).enforceClaims(types.Claims{}); err != nil {
		t.Fatalf("TDX policy without profiles unexpectedly enforced RTMR claims: %v", err)
	}
	if _, err := nodeEvidence(&ratls.Attestation{TEEType: ratls.TEETypeTDX}); err == nil {
		t.Fatal("TDX evidence without an envelope was accepted")
	}
}

func TestNodePolicyFileRejectsTrailingJSON(t *testing.T) {
	path := writeNodePolicy(t, mixedNodePolicy())
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, []byte(" {}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestNodePolicy(t, path); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("err = %v, want trailing JSON rejection", err)
	}
}

func TestNodePolicyFileRejectsUnknownJSONFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-policy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"platforms":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTestNodePolicy(t, path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v, want unknown field rejection", err)
	}
}

func TestNodePolicyFileRequiresReadOnlyMount(t *testing.T) {
	path := writeNodePolicy(t, mixedNodePolicy())
	if _, err := loadNodePolicyFile(path); err == nil || !strings.Contains(err.Error(), "read-only filesystem") {
		t.Fatalf("err = %v, want writable mount refusal", err)
	}
}

func TestOwnNodeIdentityUsesAttestedPlatformPolicy(t *testing.T) {
	r, err := loadTestNodePolicy(t, writeNodePolicy(t, mixedNodePolicy()))
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI(t, func(_ int, req types.VerifyRequest) types.VerifyResponse {
		if req.Platform != string(types.PlatformSnp) {
			t.Errorf("verify platform = %q, want snp", req.Platform)
		}
		if req.Params == nil || req.Params.AllowDebug == nil || *req.Params.AllowDebug {
			t.Error("registered policy must explicitly reject debug evidence")
		}
		if req.Params == nil || req.Params.MinTcb == nil || req.Params.MinTcb.Microcode != 2 {
			t.Error("registered SNP minimum TCB was not sent")
		}
		return verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, true)
	})
	api.attestPlatform = string(types.PlatformSnp)
	identity, err := ownNodeIdentity(context.Background(), attestationclient.NewClient(api.URL), r)
	if err != nil {
		t.Fatal(err)
	}
	if identity.platform != "sev-snp" {
		t.Errorf("RA-TLS platform = %q, want sev-snp", identity.platform)
	}
}

func TestOwnNodeIdentityFailsClosed(t *testing.T) {
	r, err := loadTestNodePolicy(t, writeNodePolicy(t, mixedNodePolicy()))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		resp types.VerifyResponse
		want error
	}{
		{"signature invalid", verifyRespPlatform(types.PlatformSnp, digestA, "", "", false, true), attestationclient.ErrSignatureInvalid},
		{"report data mismatch", verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, false), attestationclient.ErrReportDataMismatch},
		{"verified platform mismatch", verifyRespPlatform(types.PlatformTdx, digestA, rtmr1A, rtmr2A, true, true), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(tc.resp))
			api.attestPlatform = string(types.PlatformSnp)
			_, err := ownNodeIdentity(context.Background(), attestationclient.NewClient(api.URL), r)
			if err == nil {
				t.Fatal("expected own identity issuance to fail")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && !strings.Contains(err.Error(), "does not match selected policy") {
				t.Fatalf("err = %v, want verified platform mismatch", err)
			}
		})
	}
}

func TestVerifyRegisteredPeerRejectsBeforeAttestationAPI(t *testing.T) {
	r, err := loadTestNodePolicy(t, writeNodePolicy(t, mixedNodePolicy()))
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI(t, staticVerify(verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, true)))
	goodOwn := nodeIdentity{platform: "tdx", policy: r.byPlatform[string(types.PlatformTdx)]}

	for _, tc := range []struct {
		name string
		leaf *x509.Certificate
		own  nodeIdentity
	}{
		{
			name: "peer certificate expired",
			leaf: attestedLeafWindow(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)),
			own:  goodOwn,
		},
		{
			name: "RA-TLS type and envelope platform differ",
			leaf: attestedLeafPlatform(t, ratls.TEETypeSEVSNP, tdxEnvelope),
			own:  goodOwn,
		},
		{
			name: "local platform does not allow peer platform",
			leaf: attestedLeafPlatform(t, ratls.TEETypeSEVSNP, snpEnvelope),
			own: nodeIdentity{platform: "tdx", policy: compiledNodePolicy{
				platform:   string(types.PlatformTdx),
				allowPeers: map[string]bool{},
			}},
		},
		{
			name: "missing RA-TLS extension",
			leaf: plainLeaf(t),
			own:  goodOwn,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := api.verifyCalls.Load()
			if err := verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), tc.leaf, tc.own, r); err == nil {
				t.Fatal("expected peer to be denied")
			}
			if got := api.verifyCalls.Load(); got != before {
				t.Fatalf("verification calls = %d, want %d before attestation API", got, before)
			}
		})
	}
}

func TestVerifyRegisteredPeerSelectsOnlyRegisteredEvidencePolicy(t *testing.T) {
	r, err := loadTestNodePolicy(t, writeNodePolicy(t, mixedNodePolicy()))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("SNP peer uses SNP policy", func(t *testing.T) {
		leaf := attestedLeafPlatform(t, ratls.TEETypeSEVSNP, snpEnvelope)
		api := newFakeAPI(t, func(_ int, req types.VerifyRequest) types.VerifyResponse {
			if req.Platform != string(types.PlatformSnp) {
				t.Errorf("verify platform = %q, want snp", req.Platform)
			}
			return verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, true)
		})
		own := nodeIdentity{platform: "tdx", policy: r.byPlatform[string(types.PlatformTdx)]}
		if err := verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), leaf, own, r); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("raw native SNP peer is wrapped for the attestation API", func(t *testing.T) {
		leaf := rawSNPLeaf(t)
		api := newFakeAPI(t, func(_ int, req types.VerifyRequest) types.VerifyResponse {
			if req.Platform != string(types.PlatformSnp) {
				t.Errorf("verify platform = %q, want snp", req.Platform)
			}
			var inner struct {
				AttestationReport string `json:"attestation_report"`
			}
			if err := json.Unmarshal(req.Evidence, &inner); err != nil || inner.AttestationReport == "" {
				t.Errorf("raw SNP evidence = %s, want attestation_report wrapper (err=%v)", req.Evidence, err)
			}
			return verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, true)
		})
		own := nodeIdentity{platform: "tdx", policy: r.byPlatform[string(types.PlatformTdx)]}
		if err := verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), leaf, own, r); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("TDX peer needs its registered measurement and RTMR profile", func(t *testing.T) {
		leaf := attestedLeaf(t, tdxEnvelope)
		api := newFakeAPI(t, staticVerify(verifyRespPlatform(types.PlatformTdx, digestB, rtmr1A, rtmr2A, true, true)))
		own := nodeIdentity{platform: "snp", policy: r.byPlatform[string(types.PlatformSnp)]}
		if err := verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), leaf, own, r); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SNP evidence cannot select a TDX-only registry", func(t *testing.T) {
		tdxOnly := nodePolicyFile{Version: nodePolicyFileVersion, Platforms: []nodePlatformPolicy{{Platform: "tdx", Measurements: []string{digestA}, AllowPeers: []string{"tdx"}}}}
		only, err := loadTestNodePolicy(t, writeNodePolicy(t, tdxOnly))
		if err != nil {
			t.Fatal(err)
		}
		api := newFakeAPI(t, staticVerify(verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, true)))
		own := nodeIdentity{platform: "tdx", policy: only.byPlatform[string(types.PlatformTdx)]}
		err = verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeafPlatform(t, ratls.TEETypeSEVSNP, snpEnvelope), own, only)
		if err == nil || !strings.Contains(err.Error(), "no policy registered") {
			t.Fatalf("err = %v, want unregistered SNP policy error", err)
		}
		if got := api.verifyCalls.Load(); got != 0 {
			t.Errorf("verify calls = %d, want 0 before a policy exists", got)
		}
	})

	t.Run("TDX profile mismatch is denied", func(t *testing.T) {
		api := newFakeAPI(t, staticVerify(verifyRespPlatform(types.PlatformTdx, digestB, rtmr1B, rtmr2A, true, true)))
		own := nodeIdentity{platform: "snp", policy: r.byPlatform[string(types.PlatformSnp)]}
		err := verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeaf(t, tdxEnvelope), own, r)
		if err == nil || !strings.Contains(err.Error(), ErrPolicyMismatch.Error()) {
			t.Fatalf("err = %v, want TDX profile policy mismatch", err)
		}
	})

	for _, tc := range []struct {
		name string
		resp types.VerifyResponse
		want error
	}{
		{"signature failure denies peer", verifyRespPlatform(types.PlatformSnp, digestA, "", "", false, true), attestationclient.ErrSignatureInvalid},
		{"report data failure denies peer", verifyRespPlatform(types.PlatformSnp, digestA, "", "", true, false), attestationclient.ErrReportDataMismatch},
		{"verified platform mismatch denies peer", verifyRespPlatform(types.PlatformTdx, digestA, rtmr1A, rtmr2A, true, true), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(tc.resp))
			own := nodeIdentity{platform: "tdx", policy: r.byPlatform[string(types.PlatformTdx)]}
			err := verifyRegisteredPeer(context.Background(), attestationclient.NewClient(api.URL), attestedLeafPlatform(t, ratls.TEETypeSEVSNP, snpEnvelope), own, r)
			if err == nil {
				t.Fatal("expected peer denial")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && !strings.Contains(err.Error(), "does not match selected policy") {
				t.Fatalf("err = %v, want verified platform mismatch", err)
			}
		})
	}
}
