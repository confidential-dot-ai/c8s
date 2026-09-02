package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

func sealedDigest() []byte { return bytes.Repeat([]byte{0x33}, 32) }

func staticOutcome() *Outcome { return &Outcome{Verified: true} }

func TestApplyStaticAllowlistPolicy_FlagUnsetIsNoop(t *testing.T) {
	oc := staticOutcome()
	applyStaticAllowlistPolicy(oc, config{}, &evidence{}, nil, staticCAReport{})
	if !oc.Verified || oc.Error != "" || oc.StaticAllowlistDigest != "" {
		t.Fatalf("no-op expected, got %+v", oc)
	}
}

func TestApplyStaticAllowlistPolicy_Verdicts(t *testing.T) {
	cfg := config{staticAllowlist: true}
	heldMatching := &heldAllowlist{raw: []byte(`{"schema":"c8s.allowlist/v1"}`)}
	matchingDigest := sha256.Sum256(heldMatching.raw)

	for name, tc := range map[string]struct {
		ev      *evidence
		held    *heldAllowlist
		report  staticCAReport
		wantErr string // "" = verdict stays verified
	}{
		"bundle damage fails closed": {
			ev:      &evidence{},
			report:  staticCAReport{err: fmt.Errorf("two stamped CAs")},
			wantErr: "static_allowlist_malformed",
		},
		"absent stamp fails closed": {
			ev:      &evidence{},
			report:  staticCAReport{},
			wantErr: "static_allowlist_absent",
		},
		"unverified CA evidence fails closed": {
			ev:      &evidence{},
			report:  staticCAReport{digest: sealedDigest(), verifyErr: fmt.Errorf("no attestation extension")},
			wantErr: "static_allowlist_ca_unverified",
		},
		"held bytes mismatch fails closed": {
			ev:      &evidence{},
			held:    heldMatching,
			report:  staticCAReport{digest: sealedDigest()},
			wantErr: "static_allowlist_digest_mismatch",
		},
		"leaf stamped under another policy fails closed": {
			ev:      &evidence{workload: &ratls.MatchedWorkload{Name: "api", AllowlistVersion: "1", AllowlistDigest: bytes.Repeat([]byte{0x44}, 32)}},
			report:  staticCAReport{digest: sealedDigest()},
			wantErr: "static_allowlist_skew",
		},
		"consistent sealed policy verifies": {
			ev:      &evidence{workload: &ratls.MatchedWorkload{Name: "api", AllowlistVersion: "1", AllowlistDigest: matchingDigest[:]}},
			held:    heldMatching,
			report:  staticCAReport{digest: matchingDigest[:], launchDigest: "abc123"},
			wantErr: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			oc := staticOutcome()
			applyStaticAllowlistPolicy(oc, cfg, tc.ev, tc.held, tc.report)
			if tc.wantErr == "" {
				if !oc.Verified || oc.Error != "" {
					t.Fatalf("verdict = %+v, want verified", oc)
				}
				if !strings.Contains(oc.StaticAllowlistNote, "static_allowlist_verified") {
					t.Fatalf("note = %q", oc.StaticAllowlistNote)
				}
				return
			}
			if oc.Verified {
				t.Fatal("verdict stayed verified")
			}
			if !strings.Contains(oc.Error, tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", oc.Error, tc.wantErr)
			}
		})
	}
}

// sealedCAPEM writes a PEM bundle of self-signed CAs, stamping the
// static-allowlist extension onto the certificates whose index is in stamped.
func sealedCAPEM(t *testing.T, count int, stamped ...int) string {
	t.Helper()
	stampedSet := map[int]bool{}
	for _, i := range stamped {
		stampedSet[i] = true
	}
	var pemBytes []byte
	for i := 0; i < count; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("test ca %d", i)},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		if stampedSet[i] {
			ext, err := ratls.MarshalStaticAllowlistExtension(&ratls.StaticAllowlist{AllowlistDigest: sealedDigest()})
			if err != nil {
				t.Fatal(err)
			}
			tmpl.ExtraExtensions = []pkix.Extension{ext}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes = append(pemBytes, certutil.EncodeCertPEM(der)...)
	}
	path := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGatherStaticCA(t *testing.T) {
	plan := &verifyPlan{policy: &ratls.VerifyPolicy{}}

	t.Run("flag unset gathers nothing", func(t *testing.T) {
		report := gatherStaticCA(context.Background(), config{}, plan)
		if report.digest != nil || report.err != nil {
			t.Fatalf("report = %+v", report)
		}
	})

	t.Run("no stamped CA in bundle", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: sealedCAPEM(t, 1)}
		report := gatherStaticCA(context.Background(), cfg, plan)
		if report.digest != nil || report.err != nil {
			t.Fatalf("report = %+v", report)
		}
	})

	t.Run("two stamped CAs are refused", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: sealedCAPEM(t, 2, 0, 1)}
		report := gatherStaticCA(context.Background(), cfg, plan)
		if report.err == nil {
			t.Fatal("two stamped CAs were accepted")
		}
	})

	t.Run("stamped CA without evidence records verifyErr", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: sealedCAPEM(t, 2, 1)}
		report := gatherStaticCA(context.Background(), cfg, plan)
		if report.err != nil {
			t.Fatalf("bundle-level err: %v", report.err)
		}
		if !bytes.Equal(report.digest, sealedDigest()) {
			t.Fatalf("digest = %x", report.digest)
		}
		if report.verifyErr == nil {
			t.Fatal("a stamped CA with no RA-TLS extension must not verify")
		}
	})

	t.Run("unreadable bundle records err", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: filepath.Join(t.TempDir(), "missing.pem")}
		if report := gatherStaticCA(context.Background(), cfg, plan); report.err == nil {
			t.Fatal("missing bundle was accepted")
		}
	})
}

func TestBuildPolicy_StaticAllowlistRequiresMeshCA(t *testing.T) {
	_, err := buildPolicy(config{staticAllowlist: true})
	if err == nil || !strings.Contains(err.Error(), "--mesh-ca") {
		t.Fatalf("buildPolicy = %v, want --mesh-ca requirement", err)
	}
}

// tdxClaims builds a verified-claims result with the given launch digest and
// rtmr_<i> platform claims.
func tdxClaims(launch string, rtmrs map[int]string) *teetypes.VerificationResult {
	pd := map[string]any{}
	for idx, v := range rtmrs {
		pd[fmt.Sprintf("rtmr_%d", idx)] = v
	}
	return &teetypes.VerificationResult{Claims: teetypes.Claims{LaunchDigest: launch, PlatformData: pd}}
}

func TestStaticCALaunchAllowed(t *testing.T) {
	launchHex := strings.Repeat("ab", 48)
	launch, _ := hex.DecodeString(launchHex)
	rtmrHex := strings.Repeat("cd", 48)
	rtmr, _ := hex.DecodeString(rtmrHex)
	var img runtimemeasure.ImagePins
	copy(img.MRTD[:], launch)
	copy(img.RTMR1[:], rtmr)
	copy(img.RTMR2[:], rtmr)

	measured := func(m ...[]byte) *verifyPlan {
		return &verifyPlan{policy: &ratls.VerifyPolicy{Measurements: m}}
	}
	entryPlan := func(e ...measurements.Entry) *verifyPlan {
		return &verifyPlan{policy: &ratls.VerifyPolicy{Entries: e}}
	}

	for name, tc := range map[string]struct {
		result *teetypes.VerificationResult
		plan   *verifyPlan
		wantOK bool
	}{
		"unpinned accepts": {
			result: tdxClaims(launchHex, nil),
			plan:   &verifyPlan{policy: &ratls.VerifyPolicy{}},
			wantOK: true,
		},
		"measurements member": {
			result: tdxClaims(launchHex, nil),
			plan:   measured(launch),
			wantOK: true,
		},
		"measurements non-member": {
			result: tdxClaims(strings.Repeat("ef", 48), nil),
			plan:   measured(launch),
			wantOK: false,
		},
		"malformed launch digest": {
			result: tdxClaims("not-hex", nil),
			plan:   measured(launch),
			wantOK: false,
		},
		"entry digest match without RTMRs": {
			result: tdxClaims(launchHex, nil),
			plan:   entryPlan(measurements.Entry{Name: "node", Digest: launch}),
			wantOK: true,
		},
		"entry matched whole with RTMRs": {
			result: tdxClaims(launchHex, map[int]string{1: rtmrHex, 2: rtmrHex}),
			plan:   entryPlan(measurements.Entry{Name: "node", Digest: launch, RTMRs: map[int][]byte{1: rtmr, 2: rtmr}}),
			wantOK: true,
		},
		"entry RTMR mismatch": {
			result: tdxClaims(launchHex, map[int]string{1: strings.Repeat("00", 48)}),
			plan:   entryPlan(measurements.Entry{Name: "node", Digest: launch, RTMRs: map[int][]byte{1: rtmr}}),
			wantOK: false,
		},
		"no entry matches digest": {
			result: tdxClaims(strings.Repeat("ef", 48), nil),
			plan:   entryPlan(measurements.Entry{Name: "node", Digest: launch}),
			wantOK: false,
		},
		"image manifest tuple matches": {
			result: tdxClaims(launchHex, map[int]string{1: rtmrHex, 2: rtmrHex}),
			plan:   &verifyPlan{policy: &ratls.VerifyPolicy{}, pins: rtmrPins{image: &img}},
			wantOK: true,
		},
		"image manifest MRTD mismatch": {
			result: tdxClaims(strings.Repeat("ef", 48), map[int]string{1: rtmrHex, 2: rtmrHex}),
			plan:   &verifyPlan{policy: &ratls.VerifyPolicy{}, pins: rtmrPins{image: &img}},
			wantOK: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := staticCALaunchAllowed(tc.result, tc.plan)
			if tc.wantOK && err != nil {
				t.Fatalf("staticCALaunchAllowed() = %v, want nil", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("staticCALaunchAllowed() = nil, want error")
			}
		})
	}
}

func TestStaticCARTMRs(t *testing.T) {
	rtmrHex := strings.Repeat("cd", 48)
	rtmr, _ := hex.DecodeString(rtmrHex)

	if err := staticCARTMRs(tdxClaims("", nil), nil); err != nil {
		t.Fatalf("no pins must pass: %v", err)
	}
	if err := staticCARTMRs(tdxClaims("", map[int]string{1: rtmrHex}), map[int][]byte{1: rtmr}); err != nil {
		t.Fatalf("matching register: %v", err)
	}
	if err := staticCARTMRs(tdxClaims("", nil), map[int][]byte{1: rtmr}); err == nil {
		t.Fatal("missing register claim must fail closed")
	}
	if err := staticCARTMRs(tdxClaims("", map[int]string{1: "zz"}), map[int][]byte{1: rtmr}); err == nil {
		t.Fatal("malformed register claim must fail closed")
	}
	if err := staticCARTMRs(tdxClaims("", map[int]string{1: strings.Repeat("00", 48)}), map[int][]byte{1: rtmr}); err == nil {
		t.Fatal("mismatched register must fail closed")
	}
}

// The sealed-policy verdict lines render only when the check ran.
func TestRenderText_SealedPolicy(t *testing.T) {
	var out bytes.Buffer
	oc := Outcome{
		Verified:              true,
		StaticAllowlistDigest: hex.EncodeToString(sealedDigest()),
		StaticAllowlistNote:   "static_allowlist_verified: test",
	}
	renderText(config{}, oc, &out)
	if !strings.Contains(out.String(), "sealed policy: "+hex.EncodeToString(sealedDigest())) ||
		!strings.Contains(out.String(), "static_allowlist_verified") {
		t.Fatalf("renderText output missing sealed-policy lines:\n%s", out.String())
	}
}

// With --static-allowlist the held bytes are judged against the sealed CA, so
// an unnamed leaf (a front door whose pod matched no entry) passes --allowlist
// unless a name is pinned too.
func TestApplyWorkloadPolicy_StaticAllowlistToleratesUnnamedLeaf(t *testing.T) {
	held := &heldAllowlist{raw: []byte(`{"schema":"c8s.allowlist/v1"}`)}
	ev := &evidence{leaf: &x509.Certificate{}}

	oc := staticOutcome()
	applyWorkloadPolicy(oc, config{staticAllowlist: true}, ev, held)
	if !oc.Verified || oc.Error != "" {
		t.Fatalf("sealed + unnamed leaf: verdict = %+v, want verified", oc)
	}

	oc = staticOutcome()
	applyWorkloadPolicy(oc, config{staticAllowlist: true, workload: "api"}, ev, held)
	if oc.Verified || !strings.Contains(oc.Error, "workload_absent") {
		t.Fatalf("sealed + --workload on an unnamed leaf must fail: %+v", oc)
	}

	oc = staticOutcome()
	applyWorkloadPolicy(oc, config{}, ev, held)
	if oc.Verified || !strings.Contains(oc.Error, "workload_absent") {
		t.Fatalf("dynamic --allowlist on an unnamed leaf must fail: %+v", oc)
	}
}
