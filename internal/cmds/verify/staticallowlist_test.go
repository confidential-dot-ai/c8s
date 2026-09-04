package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// staticBundle writes a bundle directory holding a sealed one-entry
// static-allowlist.json (workload "web") and returns its path and the exact
// member bytes.
func staticBundle(t *testing.T) (string, []byte) {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{"web":{"containers":[{
		"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
		"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},
		"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	member, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policybundle.MemberStaticAllowlist), member, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, member
}

// staticRegister recomputes the static register straight from the convention
// in pkg/runtimemeasure, deliberately WITHOUT the helpers the code under test
// calls: Extend(Extend(Zero, SHA-384("c8s/rtmr3/mode/static/v1")),
// SHA-384("c8s/rtmr3/policy/v1:" + index)) with index the sorted, unspaced
// JSON {"static-allowlist.json": "sha256:<hex of the member>"}.
func staticRegister(member []byte) []byte {
	sum := sha256.Sum256(member)
	index := `{"static-allowlist.json":"sha256:` + hex.EncodeToString(sum[:]) + `"}`
	mode := sha512.Sum384([]byte("c8s/rtmr3/mode/static/v1"))
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(mode[:])
	afterMode := h.Sum(nil)
	policy := sha512.Sum384([]byte("c8s/rtmr3/policy/v1:" + index))
	h = sha512.New384()
	h.Write(afterMode)
	h.Write(policy[:])
	return h.Sum(nil)
}

// staticConfig is the minimal valid invocation: the bundle, the manifest, and
// the workload/mesh-CA pair the stamp check needs.
func staticConfig(t *testing.T, bundle string) config {
	t.Helper()
	_, caPath := caSignedWorkloadLeaf(t, nil)
	return config{imageManifest: writeTestManifest(t), staticAllowlist: bundle, workload: "web", meshCA: caPath}
}

func TestStaticAllowlistDerivesTheRTMR3Pin(t *testing.T) {
	dir, member := staticBundle(t)
	want := staticRegister(member)

	cfg := staticConfig(t, dir)
	plan := mustPlan(t, cfg)
	if !bytes.Equal(plan.pins.rtmr3, want) {
		t.Fatalf("derived RTMR[3] = %x, want the static register %x", plan.pins.rtmr3, want)
	}
	if plan.static == nil {
		t.Fatal("plan carries no bundle; the stamp check would have nothing to hold the leaf to")
	}

	// The loose member is the same one-member bundle.
	loose := staticConfig(t, filepath.Join(dir, policybundle.MemberStaticAllowlist))
	if got := mustPlan(t, loose).pins.rtmr3; !bytes.Equal(got, want) {
		t.Errorf("loose file RTMR[3] = %x, want the directory's %x", got, want)
	}

	// End to end: a sealed node verifies, the verdict names the register and
	// the bundle it came from.
	regHex := hex.EncodeToString(want)
	rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": regHex}
	oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
	if !oc.Verified {
		t.Fatalf("a sealed node must verify: %s", oc.Error)
	}
	if len(oc.RTMRsPinned) != 3 || oc.RTMRsPinned[2] != "3:"+regHex {
		t.Errorf("RTMRsPinned = %v, want RTMR[3] reported as %s", oc.RTMRsPinned, regHex)
	}
	sum := sha256.Sum256([]byte(`{"static-allowlist.json":"sha256:` + func() string { s := sha256.Sum256(member); return hex.EncodeToString(s[:]) }() + `"}`))
	if want := "sha256:" + hex.EncodeToString(sum[:]); oc.StaticPolicyDigest != want {
		t.Errorf("StaticPolicyDigest = %q, want the index digest %q", oc.StaticPolicyDigest, want)
	}
	var text strings.Builder
	renderText(cfg, oc, &text)
	if !strings.Contains(text.String(), "static policy: "+oc.StaticPolicyDigest) {
		t.Errorf("text verdict does not name the static policy:\n%s", text.String())
	}
}

// The pin fills the same slot as --operator-pkey and inherits its rules: a
// different register fails, an absent claim fails closed, SNP is a policy
// error naming this flag.
func TestStaticAllowlistPinEnforcedLikeOperatorPkey(t *testing.T) {
	dir, _ := staticBundle(t)
	cfg := staticConfig(t, dir)
	plan := mustPlan(t, cfg)

	t.Run("an unsealed node of the same image fails", func(t *testing.T) {
		pubPath, _, _ := operatorKeypair(t)
		dynamic := mustPlan(t, config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath})
		rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": hex.EncodeToString(dynamic.pins.rtmr3)}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "RTMR[3]") {
			t.Errorf("a dynamic-mode node must fail the static pin: %+v", oc)
		}
	})
	t.Run("a node sealed to another bundle fails", func(t *testing.T) {
		other, _ := staticBundle(t)
		otherMember := filepath.Join(other, policybundle.MemberStaticAllowlist)
		data, _ := os.ReadFile(otherMember)
		// Same document, one byte of whitespace more: the node measures bytes.
		if err := os.WriteFile(otherMember, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		reg := staticRegister(append(data, '\n'))
		rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": hex.EncodeToString(reg)}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "RTMR[3]") {
			t.Errorf("a node sealed to other bytes must fail: %+v", oc)
		}
	})
	t.Run("an absent claim fails closed", func(t *testing.T) {
		rtmrs := map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, rtmrs), nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "carry no rtmr_3") {
			t.Errorf("an unreportable register must fail closed: %+v", oc)
		}
	})
	t.Run("SNP evidence is a policy error", func(t *testing.T) {
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims:         teetypes.Claims{LaunchDigest: strings.Repeat("ab", 48)},
		}
		oc := newOutcome(cfg, &evidence{platform: "snp"}, result, nil, plan)
		if oc.Verified || !strings.Contains(oc.Error, "--static-allowlist") {
			t.Errorf("SNP has no runtime registers; the pin must be a named policy error: %+v", oc)
		}
	})
}

// cdsStamp is the policy digest CDS puts in every leaf: SHA-256 of the
// canonical document its store serves after being seeded from member. The
// store is the real one, so the test fails if seeding ever re-serializes a
// sealed member differently from the bytes the node measured.
func cdsStamp(t *testing.T, member []byte) []byte {
	t.Helper()
	al, err := pkgallowlist.ParseJSON(member)
	if err != nil {
		t.Fatal(err)
	}
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.SeedWorkloads(al.Workloads); err != nil {
		t.Fatal(err)
	}
	served, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := served.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// The bundle member is the allowlist the stamp is held to: the leaf's stamped
// digest must be SHA-256 of the measured bytes and the stamped name must
// resolve in it, exactly as --allowlist would have checked a held file. The
// stamp comes from CDS's own store round trip, not from hashing the member,
// so the check proves the two sides agree on the bytes.
func TestStaticAllowlistHoldsTheStamp(t *testing.T) {
	dir, member := staticBundle(t)
	stamp := cdsStamp(t, member)
	if measured := sha256.Sum256(member); !bytes.Equal(stamp, measured[:]) {
		t.Fatalf("CDS would stamp %x but the node measured %x: the member is not in the store's form", stamp, measured)
	}
	cfg := staticConfig(t, dir)
	plan := mustPlan(t, cfg)
	held, err := heldFromBundle(plan.static)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(held.raw, member) {
		t.Fatal("held bytes differ from the member; the digest compare would hash a re-serialization")
	}

	run := func(matched *ratls.MatchedWorkload) Outcome {
		t.Helper()
		leaf, caPath := caSignedWorkloadLeaf(t, matched)
		cfg := cfg
		cfg.meshCA = caPath
		oc := Outcome{Verified: true}
		applySandboxPolicy(&oc, cfg, &evidence{leaf: leaf, workload: matched}, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
		applyWorkloadPolicy(&oc, cfg, &evidence{leaf: leaf, workload: matched}, held)
		return oc
	}
	if oc := run(&ratls.MatchedWorkload{Name: "web", AllowlistVersion: "1", AllowlistDigest: stamp}); !oc.Verified {
		t.Errorf("a leaf stamped with the bundle's digest must verify: %s", oc.Error)
	}
	other := sha256.Sum256(append(bytes.Clone(member), '\n'))
	if oc := run(&ratls.MatchedWorkload{Name: "web", AllowlistVersion: "1", AllowlistDigest: other[:]}); oc.Verified || !strings.Contains(oc.Error, "allowlist_digest_mismatch") || !strings.Contains(oc.Error, "held --static-allowlist bytes") || strings.Contains(oc.Error, "--allowlist bytes") {
		t.Errorf("a leaf stamped with another policy's digest must fail naming --static-allowlist: %+v", oc)
	}
	if oc := run(&ratls.MatchedWorkload{Name: "other", AllowlistVersion: "1", AllowlistDigest: stamp}); oc.Verified || !strings.Contains(oc.Error, "workload_name_mismatch") {
		t.Errorf("a leaf stamped for another entry must fail: %+v", oc)
	}
}

func TestStaticAllowlistFlagErrors(t *testing.T) {
	dir, member := staticBundle(t)
	manifest := writeTestManifest(t)
	pubPath, _, _ := operatorKeypair(t)
	_, caPath := caSignedWorkloadLeaf(t, nil)
	unsealed := t.TempDir()
	if err := os.WriteFile(filepath.Join(unsealed, policybundle.MemberStaticAllowlist), append(member, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	nullDigests := t.TempDir()
	if err := os.WriteFile(filepath.Join(nullDigests, policybundle.MemberStaticAllowlist), bytes.Replace(member, []byte(`"digests":{}`), []byte(`"digests":null`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := config{imageManifest: manifest, staticAllowlist: dir, workload: "web", meshCA: caPath}
	with := func(mutate func(c *config)) config {
		c := valid
		mutate(&c)
		return c
	}

	for _, tc := range []struct {
		name string
		cfg  config
		want []string
	}{
		{"with --operator-pkey", with(func(c *config) { c.operatorPubkey = pubPath }),
			[]string{"--operator-pkey", "--static-allowlist", "name the register once"}},
		{"with --expected-rtmr3", with(func(c *config) { c.expectedRTMR3Hex = testRTMR3 }),
			[]string{"--expected-rtmr3", "--static-allowlist", "name the register once"}},
		{"with --rtmr 3=", with(func(c *config) { c.rtmrs = []string{"3=" + testRTMR3} }),
			[]string{"--rtmr 3=", "--static-allowlist", "name the register once"}},
		{"without --image-manifest", with(func(c *config) { c.imageManifest = "" }),
			[]string{"--static-allowlist requires --image-manifest"}},
		{"without --workload", with(func(c *config) { c.workload = "" }),
			[]string{"--static-allowlist requires --workload"}},
		{"without --mesh-ca", with(func(c *config) { c.meshCA = "" }),
			[]string{"--workload requires --mesh-ca"}},
		{"with --allowlist", with(func(c *config) { c.allowlistFile = filepath.Join(dir, policybundle.MemberStaticAllowlist) }),
			[]string{"--allowlist cannot be combined with --static-allowlist"}},
		{"iso image", with(func(c *config) { c.staticAllowlist = filepath.Join(dir, "policydata.iso") }),
			[]string{"--static-allowlist", "ISO images cannot be read here"}},
		{"missing bundle", with(func(c *config) { c.staticAllowlist = filepath.Join(dir, "absent") }),
			[]string{"--static-allowlist"}},
		{"member not sealed", with(func(c *config) { c.staticAllowlist = unsealed }),
			[]string{"--static-allowlist static-allowlist.json", "not its canonical form"}},
		{"member not in the store's form", with(func(c *config) { c.staticAllowlist = nullDigests }),
			[]string{"--static-allowlist static-allowlist.json", `"digests" must be {}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildPolicy(tc.cfg)
			if err == nil {
				t.Fatal("want a usage error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			var out, errOut strings.Builder
			if code := run(context.Background(), tc.cfg, &out, &errOut); code != exitUsage {
				t.Errorf("run code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
			}
		})
	}

	if plan := mustPlan(t, valid); !bytes.Equal(plan.pins.rtmr3, staticRegister(member)) {
		t.Error("the valid case must still resolve the derived pin")
	}
}
