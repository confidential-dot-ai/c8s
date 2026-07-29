package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const seedJSON = `{"schema":"c8s.allowlist/v1","digests":{"sha256:` +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `":"cds"}}`

func TestExpectedSeedDigestFromSeedFile(t *testing.T) {
	seed, err := pkgallowlist.ParseJSON([]byte(seedJSON))
	if err != nil {
		t.Fatal(err)
	}
	want, err := seed.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}

	got, err := expectedSeedDigest(config{allowlistSeed: writeTemp(t, "seed.json", seedJSON)})
	if err != nil {
		t.Fatalf("expectedSeedDigest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("digest = %x, want the canonical seed digest %x", got, want)
	}

	if _, err := expectedSeedDigest(config{allowlistSeed: "/does/not/exist"}); err == nil {
		t.Fatal("unreadable --allowlist-seed accepted")
	}
	if _, err := expectedSeedDigest(config{allowlistSeed: writeTemp(t, "bad.json", "not json")}); err == nil {
		t.Fatal("malformed --allowlist-seed accepted")
	}
}

func TestExpectedAllowlistDigestFlags(t *testing.T) {
	if _, err := expectedAllowlistDigest(config{allowlistFile: "a", allowlistDigestHex: "b"}); err == nil {
		t.Fatal("mutually exclusive flags accepted")
	}
	if _, err := expectedAllowlistDigest(config{allowlistDigestHex: "zz"}); err == nil {
		t.Fatal("malformed hex digest accepted")
	}
	if _, err := expectedAllowlistDigest(config{allowlistDigestHex: "abcd"}); err == nil {
		t.Fatal("wrong-length digest accepted")
	}

	want := bytes.Repeat([]byte{0xAB}, sha256.Size)
	got, err := expectedAllowlistDigest(config{allowlistDigestHex: " " + hex.EncodeToString(want) + "\n"})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("digest = %x, err = %v", got, err)
	}

	// The file is hashed verbatim: the pin is over the exact GET /allowlist
	// response bytes, with no parsing or normalization in between.
	raw := "  {\"any\": \"bytes at all\"}\n"
	sum := sha256.Sum256([]byte(raw))
	got, err = expectedAllowlistDigest(config{allowlistFile: writeTemp(t, "allowlist.json", raw)})
	if err != nil || !bytes.Equal(got, sum[:]) {
		t.Fatalf("file digest = %x, err = %v, want %x", got, err, sum[:])
	}

	if _, err := expectedAllowlistDigest(config{allowlistFile: "/does/not/exist"}); err == nil {
		t.Fatal("unreadable --allowlist accepted")
	}
	if d, err := expectedAllowlistDigest(config{}); err != nil || d != nil {
		t.Fatalf("no flags: digest=%x err=%v, want nil/nil", d, err)
	}
}

func TestExpectedMeshCADigestFlags(t *testing.T) {
	if _, err := expectedMeshCADigest(config{meshCA: "a", meshCADigestHex: "b"}); err == nil {
		t.Fatal("mutually exclusive flags accepted")
	}
	if _, err := expectedMeshCADigest(config{meshCADigestHex: "zz"}); err == nil {
		t.Fatal("malformed hex digest accepted")
	}
	if _, err := expectedMeshCADigest(config{meshCADigestHex: "abcd"}); err == nil {
		t.Fatal("wrong-length digest accepted")
	}

	want := bytes.Repeat([]byte{0xCD}, sha256.Size)
	got, err := expectedMeshCADigest(config{meshCADigestHex: hex.EncodeToString(want)})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("digest = %x, err = %v", got, err)
	}

	// kind=cds + --mesh-ca digests the certificate DER, matching what CDS
	// commits (sha256 of mesh.Cert.Raw).
	pemStr, _ := selfSignedCertPEM(t)
	block, _ := pem.Decode([]byte(pemStr))
	sum := sha256.Sum256(block.Bytes)
	got, err = expectedMeshCADigest(config{kind: "cds", meshCA: writeTemp(t, "ca.pem", pemStr)})
	if err != nil || !bytes.Equal(got, sum[:]) {
		t.Fatalf("PEM digest = %x, err = %v, want %x", got, err, sum[:])
	}

	if _, err := expectedMeshCADigest(config{kind: "cds", meshCA: "/does/not/exist"}); err == nil {
		t.Fatal("unreadable --mesh-ca accepted for kind=cds")
	}
	if _, err := expectedMeshCADigest(config{kind: "cds", meshCA: writeTemp(t, "notpem.pem", "not a pem")}); err == nil {
		t.Fatal("non-PEM --mesh-ca accepted for kind=cds")
	}

	// For any other kind --mesh-ca keeps its chain-check meaning and pins
	// nothing here.
	if d, err := expectedMeshCADigest(config{kind: "lb", meshCA: writeTemp(t, "ca2.pem", pemStr)}); err != nil || d != nil {
		t.Fatalf("kind=lb: digest=%x err=%v, want nil/nil", d, err)
	}
}

func TestExpectedRTMRPinsIndividualFlags(t *testing.T) {
	r1 := strings.Repeat("11", 48)
	r2 := strings.Repeat("22", 48)
	pins, mrtd, err := expectedRTMRPins(config{expectedRTMR1Hex: r1, expectedRTMR2Hex: r2})
	if err != nil {
		t.Fatalf("expectedRTMRPins: %v", err)
	}
	if mrtd != nil {
		t.Fatalf("manifestMRTD = %x without --image-manifest", mrtd)
	}
	if hex.EncodeToString(pins[1]) != r1 || hex.EncodeToString(pins[2]) != r2 {
		t.Fatalf("pins = [1]%x [2]%x, want the flag values", pins[1], pins[2])
	}

	if _, _, err := expectedRTMRPins(config{expectedRTMR1Hex: "zz"}); err == nil {
		t.Fatal("malformed --expected-rtmr1 accepted")
	}
	if _, _, err := expectedRTMRPins(config{expectedRTMR2Hex: "abcd"}); err == nil {
		t.Fatal("wrong-length --expected-rtmr2 accepted")
	}
}

func TestExpectedRTMRPinsManifestFieldErrors(t *testing.T) {
	if _, _, err := expectedRTMRPins(config{imageManifest: "/does/not/exist"}); err == nil {
		t.Fatal("unreadable --image-manifest accepted")
	}

	mrtd := strings.Repeat("aa", 48)
	r2 := strings.Repeat("cc", 48)
	badR1 := `{"tdx":{"mrtd":"` + mrtd + `","rtmr1":"zz","rtmr2":"` + r2 + `"}}`
	if _, _, err := expectedRTMRPins(config{imageManifest: writeTemp(t, "m1.json", badR1)}); err == nil {
		t.Fatal("malformed tdx.rtmr1 accepted")
	}

	r1 := strings.Repeat("bb", 48)
	badR2 := `{"tdx":{"mrtd":"` + mrtd + `","rtmr1":"` + r1 + `","rtmr2":"abcd"}}`
	if _, _, err := expectedRTMRPins(config{imageManifest: writeTemp(t, "m2.json", badR2)}); err == nil {
		t.Fatal("wrong-length tdx.rtmr2 accepted")
	}
}

func TestBuildPolicyPropagatesPinErrors(t *testing.T) {
	for name, cfg := range map[string]config{
		"bad rtmr1":            {expectedRTMR1Hex: "zz"},
		"bad seed digest":      {allowlistSeedDigest: "zz"},
		"bad mesh-ca digest":   {meshCADigestHex: "zz"},
		"bad allowlist digest": {allowlistDigestHex: "zz"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPolicy(cfg); err == nil {
				t.Fatal("buildPolicy accepted an invalid pin flag")
			}
		})
	}
}

func TestBuildPolicyImageManifestOverridesMeasurements(t *testing.T) {
	// --image-manifest is the one-flag form of the whole image pin: the MRTD
	// from the manifest replaces any --measurements value, so the three
	// registers cannot drift apart.
	mrtd := strings.Repeat("aa", 48)
	manifest := `{"tdx":{"mrtd":"` + mrtd + `","rtmr1":"` + strings.Repeat("bb", 48) +
		`","rtmr2":"` + strings.Repeat("cc", 48) + `"}}`
	policy, err := buildPolicy(config{
		imageManifest: writeTemp(t, "manifest.json", manifest),
		measurements:  []string{strings.Repeat("dd", 48)},
	})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if len(policy.Measurements) != 1 || hex.EncodeToString(policy.Measurements[0]) != mrtd {
		t.Fatalf("Measurements = %x, want only the manifest MRTD %s", policy.Measurements, mrtd)
	}
	if len(policy.ExpectedRTMRs[1]) == 0 || len(policy.ExpectedRTMRs[2]) == 0 {
		t.Fatal("manifest RTMR[1]/[2] pins not set")
	}
}

// claimsV3 is a fully populated (post-#168) claims set: mesh-CA and
// live-allowlist digests present, workload digest set (pre-#168 shape).
func claimsV3(t *testing.T) *ratls.ConfigClaims {
	t.Helper()
	return &ratls.ConfigClaims{
		OperatorKeysDigest: bytes.Repeat([]byte{0x01}, ratls.ClaimsDigestSize),
		SeedDigest:         bytes.Repeat([]byte{0x02}, ratls.ClaimsDigestSize),
		WorkloadDigest:     bytes.Repeat([]byte{0x03}, ratls.ClaimsDigestSize),
		MeshCADigest:       bytes.Repeat([]byte{0x04}, ratls.ClaimsDigestSize),
		AllowlistDigest:    bytes.Repeat([]byte{0x05}, ratls.ClaimsDigestSize),
	}
}

func TestApplyClaimsPolicyMeshCAAndAllowlistPins(t *testing.T) {
	claims := claimsV3(t)
	otherDigest := bytes.Repeat([]byte{0xEE}, ratls.ClaimsDigestSize)

	cases := []struct {
		name         string
		policy       *ratls.VerifyPolicy
		wantVerified bool
	}{
		{"mesh-ca pin matches", &ratls.VerifyPolicy{MeshCADigest: claims.MeshCADigest}, true},
		{"mesh-ca pin mismatch", &ratls.VerifyPolicy{MeshCADigest: otherDigest}, false},
		{"allowlist pin matches", &ratls.VerifyPolicy{AllowlistDigest: claims.AllowlistDigest}, true},
		{"allowlist pin mismatch", &ratls.VerifyPolicy{AllowlistDigest: otherDigest}, false},
		{"mesh-ca pin without claims is fail-closed", &ratls.VerifyPolicy{MeshCADigest: claims.MeshCADigest}, false},
		{"allowlist pin without claims is fail-closed", &ratls.VerifyPolicy{AllowlistDigest: claims.AllowlistDigest}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &evidence{configClaims: claims}
			if strings.Contains(tc.name, "without claims") {
				ev = &evidence{}
			}
			oc := Outcome{Verified: true}
			applyClaimsPolicy(&oc, ev, tc.policy, operatorKeysReport{})
			if oc.Verified != tc.wantVerified {
				t.Fatalf("Verified = %t (error %q), want %t", oc.Verified, oc.Error, tc.wantVerified)
			}
		})
	}
}

func TestApplyClaimsPolicySurfacesV3Digests(t *testing.T) {
	claims := claimsV3(t)
	oc := Outcome{Verified: true}
	applyClaimsPolicy(&oc, &evidence{configClaims: claims}, &ratls.VerifyPolicy{}, operatorKeysReport{})
	if oc.AllowlistAttestedDigest != hex.EncodeToString(claims.AllowlistDigest) {
		t.Fatalf("AllowlistAttestedDigest = %q", oc.AllowlistAttestedDigest)
	}
	if oc.WorkloadAttestedDigest != hex.EncodeToString(claims.WorkloadDigest) {
		t.Fatalf("WorkloadAttestedDigest = %q", oc.WorkloadAttestedDigest)
	}

	// Pre-v3 claims never say "no allowlist served" — they say the target
	// predates the field, so staleness cannot masquerade as an empty policy.
	old := testClaims(0x01, 0x02)
	oc = Outcome{Verified: true}
	applyClaimsPolicy(&oc, &evidence{configClaims: old}, &ratls.VerifyPolicy{}, operatorKeysReport{})
	if !strings.Contains(oc.AllowlistAttestedDigest, "not attested") {
		t.Fatalf("v1/v2 AllowlistAttestedDigest = %q, want the predates-v3 label", oc.AllowlistAttestedDigest)
	}
}

func TestApplyClaimsPolicyMatchedWorkload(t *testing.T) {
	entriesDigest := bytes.Repeat([]byte{0x77}, ratls.ClaimsDigestSize)

	t.Run("stamp surfaced, ambiguity flagged", func(t *testing.T) {
		oc := Outcome{Verified: true}
		mw := &ratls.MatchedWorkload{Names: []string{"api", "worker"}, EntriesDigest: entriesDigest}
		applyClaimsPolicy(&oc, &evidence{matchedWorkload: mw}, &ratls.VerifyPolicy{}, operatorKeysReport{})
		if !oc.Verified {
			t.Fatalf("Verified = false (error %q)", oc.Error)
		}
		if len(oc.MatchedWorkloadEntries) != 2 || !oc.MatchedWorkloadAmbiguous {
			t.Fatalf("entries = %v ambiguous = %t", oc.MatchedWorkloadEntries, oc.MatchedWorkloadAmbiguous)
		}
		if oc.MatchedWorkloadEntriesDigest != hex.EncodeToString(entriesDigest) {
			t.Fatalf("EntriesDigest = %q", oc.MatchedWorkloadEntriesDigest)
		}
	})

	t.Run("unparseable stamp fails closed", func(t *testing.T) {
		// A malformed stamp must not read as "no stamp": that is exactly how a
		// tampered leaf would try to shed its workload identity.
		oc := Outcome{Verified: true}
		applyClaimsPolicy(&oc, &evidence{matchedErr: errTest("bad DER")}, &ratls.VerifyPolicy{}, operatorKeysReport{})
		if oc.Verified || !strings.Contains(oc.Error, "matched-workload") {
			t.Fatalf("Verified = %t error = %q", oc.Verified, oc.Error)
		}
	})
}

func u8(v uint8) *uint8 { return &v }

func TestFormatTCB(t *testing.T) {
	snp := teetypes.TcbInfo{Type: "Snp", Bootloader: u8(3), Tee: u8(0), Snp: u8(8), Microcode: u8(209)}
	if got := formatTCB(snp); got != "bootloader=3 tee=0 snp=8 microcode=209" {
		t.Fatalf("SNP TCB = %q", got)
	}
	snp.FMC = u8(1)
	if got := formatTCB(snp); !strings.HasSuffix(got, " fmc=1") {
		t.Fatalf("Turin TCB = %q, want fmc suffix", got)
	}
	// Absent components render as 0 rather than crashing on the nil pointer.
	if got := formatTCB(teetypes.TcbInfo{Type: "Snp"}); got != "bootloader=0 tee=0 snp=0 microcode=0" {
		t.Fatalf("nil-component TCB = %q", got)
	}
	tdx := teetypes.TcbInfo{Type: "Tdx", TCBSvn: []byte{0x01, 0x02}}
	if got := formatTCB(tdx); got != "svn=0102" {
		t.Fatalf("TDX TCB = %q", got)
	}
	if got := formatTCB(teetypes.TcbInfo{Type: "Tdx"}); got != "" {
		t.Fatalf("empty TDX TCB = %q, want \"\"", got)
	}
	if got := formatTCB(teetypes.TcbInfo{}); got != "" {
		t.Fatalf("unknown TCB type = %q, want \"\"", got)
	}
}

func TestNewOutcomeSurfacesRTMRPins(t *testing.T) {
	pin := bytes.Repeat([]byte{0x42}, 48)
	policy := &ratls.VerifyPolicy{ExpectedRTMRs: [4][]byte{1: pin, 3: pin}}
	oc := newOutcome(config{}, &evidence{platform: "tdx"}, &teetypes.VerificationResult{SignatureValid: true}, nil, policy)
	want := []string{"1:" + hex.EncodeToString(pin), "3:" + hex.EncodeToString(pin)}
	if len(oc.RTMRsPinned) != 2 || oc.RTMRsPinned[0] != want[0] || oc.RTMRsPinned[1] != want[1] {
		t.Fatalf("RTMRsPinned = %v, want %v", oc.RTMRsPinned, want)
	}
}

func TestRenderTextClaimsSections(t *testing.T) {
	pinHex := strings.Repeat("42", 48)
	base := Outcome{
		Verified: true, Backend: "attestation-go", Platform: "tdx",
		Fresh: true, Pinned: true,
	}

	t.Run("all identity sections rendered", func(t *testing.T) {
		oc := base
		oc.RTMRsPinned = []string{"3:" + pinHex}
		oc.SandboxID = "sandbox-1"
		oc.SandboxIDNote = "verified: the leaf chains to the supplied mesh CA"
		oc.OperatorKeysAttestedDigest = strings.Repeat("01", 32)
		oc.AllowlistAttestedDigest = strings.Repeat("05", 32)
		oc.SeedAttestedDigest = strings.Repeat("02", 32)
		oc.WorkloadAttestedDigest = strings.Repeat("03", 32)
		oc.MatchedWorkloadEntries = []string{"api"}
		oc.MatchedWorkloadEntriesDigest = strings.Repeat("77", 32)
		oc.OperatorKeys = []string{strings.Repeat("aa", 32)}

		var out bytes.Buffer
		renderText(config{}, oc, &out)
		s := out.String()
		for _, want := range []string{
			"RTMR[3]:", "operator key / workloads",
			"sandbox id:   sandbox-1",
			"operator-keys digest (attested via config-claims)",
			"live allowlist digest (attested via config-claims)",
			"allowlist-seed digest (attested via config-claims)",
			"workload digest (attested via config-claims)",
			"matched workload entry (stamped by CDS): api",
			"entries digest: sha256:" + strings.Repeat("77", 32),
			"served list matches the attested digest",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("output missing %q:\n%s", want, s)
			}
		}
		if strings.Contains(s, "AMBIGUOUS") {
			t.Errorf("single matched entry rendered as ambiguous:\n%s", s)
		}
	})

	t.Run("ambiguous matched entries say so", func(t *testing.T) {
		oc := base
		oc.MatchedWorkloadEntries = []string{"api", "worker"}
		oc.MatchedWorkloadAmbiguous = true
		oc.MatchedWorkloadEntriesDigest = strings.Repeat("77", 32)

		var out bytes.Buffer
		renderText(config{}, oc, &out)
		if !strings.Contains(out.String(), "AMBIGUOUS") || !strings.Contains(out.String(), "api, worker") {
			t.Errorf("ambiguous stamp not flagged:\n%s", out.String())
		}
	})

	t.Run("tdx without RTMR pins warns", func(t *testing.T) {
		// A TDX verdict with only an MRTD pin proves neither the guest image
		// nor the deployment; the text output must not look like one that does.
		var out bytes.Buffer
		renderText(config{}, base, &out)
		if !strings.Contains(out.String(), "no RTMR pinned") {
			t.Errorf("missing the unpinned-RTMR warning:\n%s", out.String())
		}
	})
}
