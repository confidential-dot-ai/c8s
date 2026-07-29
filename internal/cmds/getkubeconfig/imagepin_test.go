package getkubeconfig

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// THE attack this gate exists to stop.
//
// RTMR[3] = SHA384(0x00*48 ‖ SHA384(operator PUBLIC key)), and the launcher —
// the untrusted host, per docs/THREAT_MODEL.md — is what stages that key on the
// opkeydata disk the initrd measures. So the host can boot ANY guest image with
// the operator's key staged and reproduce RTMR[3] byte for byte. Here the node
// presents a genuine, nonce-bound quote with the correct RTMR[3] and a guest
// image that is not the operator's: it must be refused, because the node is
// what supplies the CA and client cert the resulting kubeconfig trusts.
func TestRunRejectsForeignImageWithCorrectRTMR3(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
	pub := operatorPubFromKeyFile(t, env.keyPath)

	// Attacker's image: different MRTD, kernel and rootfs — same operator key.
	evil := verifiedResult(expectedRTMR3(pub))
	evil.Claims.LaunchDigest = strings.Repeat("ab", 48)
	evil.Claims.PlatformData["rtmr_1"] = strings.Repeat("cd", 48)
	evil.Claims.PlatformData["rtmr_2"] = strings.Repeat("ef", 48)
	stubVerify(t, evil, nil)

	var releaseHits atomic.Int32
	release := newCountingRelease(t, &releaseHits)
	cfg := env.config()
	cfg.ReleaseBaseURL = release

	err := Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("Run accepted a foreign guest image carrying the correct RTMR[3]")
	}
	if !strings.Contains(err.Error(), "attestation gate") {
		t.Fatalf("want the failure at the attestation gate, got %v", err)
	}
	if n := releaseHits.Load(); n != 0 {
		t.Fatalf("cred-release hits = %d, want 0 (no credential may be requested from an unexpected image)", n)
	}
}

// The same substitution one register at a time: MRTD pins the firmware,
// RTMR[1] the kernel, RTMR[2] the rootfs. Each alone must sink the run, since
// each is a distinct way to boot software the operator did not audit.
func TestRunRejectsEachImageRegisterIndependently(t *testing.T) {
	for name, mutate := range map[string]func(r map[string]any, launch *string){
		"MRTD (firmware)": func(_ map[string]any, launch *string) { *launch = strings.Repeat("ab", 48) },
		"RTMR[1] (kernel)": func(r map[string]any, _ *string) {
			r["rtmr_1"] = strings.Repeat("cd", 48)
		},
		"RTMR[2] (rootfs)": func(r map[string]any, _ *string) {
			r["rtmr_2"] = strings.Repeat("ef", 48)
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
			pub := operatorPubFromKeyFile(t, env.keyPath)
			res := verifiedResult(expectedRTMR3(pub))
			mutate(res.Claims.PlatformData, &res.Claims.LaunchDigest)
			stubVerify(t, res, nil)

			if err := Run(context.Background(), env.config()); err == nil {
				t.Fatalf("Run accepted a node whose %s does not match the pinned image", name)
			}
		})
	}
}

// The happy path still works: the operator's own image, the operator's own key.
func TestRunAcceptsPinnedImage(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
	if err := Run(context.Background(), env.config()); err != nil {
		t.Fatalf("Run rejected the pinned image: %v", err)
	}
}

// The policy that reaches the verifier must be the full one. Emulated
// enforcement in the stub could hide a get-kubeconfig bug that simply forgets
// to pass a register, so assert the params directly.
func TestRunPassesFullPolicyToVerifier(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
	pub := operatorPubFromKeyFile(t, env.keyPath)
	got := stubVerify(t, verifiedResult(expectedRTMR3(pub)), nil)

	if err := Run(context.Background(), env.config()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(got.Measurements) != 1 || hex.EncodeToString(got.Measurements[0]) != testMRTD {
		t.Errorf("MRTD pin = %x, want %s", got.Measurements, testMRTD)
	}
	for i, want := range map[int]string{1: testRTMR1, 2: testRTMR2, 3: expectedRTMR3(pub)} {
		if got.ExpectedRTMRs[i] == nil {
			t.Errorf("RTMR[%d] was not pinned", i)
			continue
		}
		if h := hex.EncodeToString(got.ExpectedRTMRs[i]); h != want {
			t.Errorf("RTMR[%d] pin = %s, want %s", i, h, want)
		}
	}
	if got.ExpectedReportData == nil {
		t.Error("report_data binding was not passed")
	}
}

// An unpinned run must not happen at all — not even reach the network. An
// optional pin would leave every operator who omits it exactly where the
// vulnerability was.
func TestRunRefusesWithoutImagePin(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
	var releaseHits atomic.Int32
	release := newCountingRelease(t, &releaseHits)

	cfg := env.config()
	cfg.Image = ImagePolicy{}
	cfg.ReleaseBaseURL = release

	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "guest-image pin") {
		t.Fatalf("want a refusal naming the missing image pin, got %v", err)
	}
	if n := releaseHits.Load(); n != 0 {
		t.Fatalf("cred-release hits = %d, want 0", n)
	}
}

// A partial pin is refused rather than treated as better than nothing: MRTD
// covers only the firmware, so pinning it alone reports the same verdict shape
// while leaving the guest OS unconstrained.
func TestImagePolicyRejectsPartialPin(t *testing.T) {
	pub := operatorPub(t)
	for name, p := range map[string]ImagePolicy{
		"MRTD only":            {MeasurementHex: testMRTD},
		"MRTD + RTMR[1] only":  {MeasurementHex: testMRTD, RTMR1Hex: testRTMR1},
		"registers, no MRTD":   {RTMR1Hex: testRTMR1, RTMR2Hex: testRTMR2},
		"manifest + registers": {ManifestPath: writeTestManifest(t), RTMR1Hex: testRTMR1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.resolve(pub); err == nil {
				t.Fatal("resolve accepted a partial image pin")
			}
		})
	}
}

// The individual flags are equivalent to the manifest, for an operator who has
// the digests but not the file.
func TestImagePolicyIndividualFlagsMatchManifest(t *testing.T) {
	pub := operatorPub(t)
	fromManifest, err := ImagePolicy{ManifestPath: writeTestManifest(t)}.resolve(pub)
	if err != nil {
		t.Fatal(err)
	}
	fromFlags, err := ImagePolicy{
		MeasurementHex: testMRTD,
		RTMR1Hex:       testRTMR1,
		RTMR2Hex:       testRTMR2,
	}.resolve(pub)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(fromFlags.measurements[0]) != hex.EncodeToString(fromManifest.measurements[0]) {
		t.Error("MRTD differs between the manifest and the individual flags")
	}
	for i := range fromFlags.rtmrs {
		if hex.EncodeToString(fromFlags.rtmrs[i]) != hex.EncodeToString(fromManifest.rtmrs[i]) {
			t.Errorf("RTMR[%d] differs between the manifest and the individual flags", i)
		}
	}
}

// RTMR[3] is derived from the operator's key file bytes VERBATIM, matching the
// initrd — the seed convention lives in pkg/runtimemeasure and this must not
// re-derive it.
func TestImagePolicySeedsRTMR3FromOperatorKey(t *testing.T) {
	pub := operatorPub(t)
	p, err := ImagePolicy{ManifestPath: writeTestManifest(t)}.resolve(pub)
	if err != nil {
		t.Fatal(err)
	}
	want := runtimemeasure.ForOperatorKey(pub)
	if hex.EncodeToString(p.rtmrs[3]) != hex.EncodeToString(want[:]) {
		t.Error("RTMR[3] pin does not match runtimemeasure.ForOperatorKey")
	}
}

// A malformed or non-TDX manifest is a usage error, not a silently weaker pin.
func TestImagePolicyRejectsBadManifest(t *testing.T) {
	pub := operatorPub(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"not json":       `{`,
		"no tdx section": `{"build":{"platform":"snp"}}`,
		"missing rtmr2":  `{"tdx":{"mrtd":"` + testMRTD + `","rtmr1":"` + testRTMR1 + `"}}`,
		"short mrtd":     `{"tdx":{"mrtd":"abcd","rtmr1":"` + testRTMR1 + `","rtmr2":"` + testRTMR2 + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (ImagePolicy{ManifestPath: path}).resolve(pub); err == nil {
				t.Fatal("resolve accepted a malformed manifest")
			}
		})
	}
	if _, err := (ImagePolicy{ManifestPath: filepath.Join(dir, "absent.json")}).resolve(pub); err == nil {
		t.Fatal("resolve accepted a missing manifest")
	}
}

// The RA-TLS dial enforces the same policy as the attest gate: a node that
// passes the gate must not be able to present a different image on :8443.
func TestRATLSDialEnforcesImagePin(t *testing.T) {
	pub := operatorPub(t)
	res := verifiedResult(expectedRTMR3(pub))
	res.Claims.PlatformData["rtmr_2"] = strings.Repeat("ef", 48) // different rootfs
	stubVerify(t, res, nil)
	cert := attestedTDXCert(t)

	err := verifyServerCert(context.Background(), cert, testPins(t, pub))
	if err == nil {
		t.Fatal("RA-TLS dial accepted a serving cert from a foreign image")
	}
	if !errors.Is(err, localverify.ErrRTMRNotAllowed) {
		t.Fatalf("want an RTMR policy failure, got %v", err)
	}
}
