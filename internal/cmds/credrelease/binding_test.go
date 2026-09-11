package credrelease

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var operatorPub = []byte("operator public key bytes")

// TestMain shortens the attestation-api readiness wait so the unreachable-URL
// cases fail in milliseconds rather than the 90s a real boot allows.
func TestMain(m *testing.M) {
	attestationReadyTimeout = 300 * time.Millisecond
	attestationReadyInterval = 20 * time.Millisecond
	os.Exit(m.Run())
}

// stageOperatorPubkey points the package's staging path at a temp file and
// writes pub to it. Pass nil to leave the file absent.
func stageOperatorPubkey(t *testing.T, pub []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-pubkey")
	orig := operatorPubkeyPath
	operatorPubkeyPath = path
	t.Cleanup(func() { operatorPubkeyPath = orig })
	if pub == nil {
		return
	}
	if err := os.WriteFile(path, pub, 0o600); err != nil {
		t.Fatal(err)
	}
}

// selfReport is what a stub attestation-api's verified self-report carries:
// the operator-key binding in whichever claim the platform uses (RTMR[3] on
// TDX, HOSTDATA on SEV-SNP), the launch digest, and on TDX the RTMR[1]/[2]
// pins. Zero-valued fields are left off the claims.
type selfReport struct {
	platform     teetypes.PlatformType
	binding      []byte
	launchDigest []byte
	rtmr1, rtmr2 []byte
}

// stubAttester serves a fake attestation-api answering r as this guest's
// verified self-report.
func stubAttester(t *testing.T, r selfReport) *testattest.Stub {
	t.Helper()
	stub := testattest.New(t)
	stub.SetPlatform(types.Platform(r.platform))
	v := testattest.PassingVerdict(hex.EncodeToString(r.launchDigest))
	if r.platform.IsTDX() {
		pd := map[string]any{}
		for k, b := range map[string][]byte{"rtmr_1": r.rtmr1, "rtmr_2": r.rtmr2, "rtmr_3": r.binding} {
			if b != nil {
				pd[k] = hex.EncodeToString(b)
			}
		}
		v.Claims.PlatformData = pd
	} else {
		v.Claims.InitData = r.binding
	}
	stub.SetVerdict(v)
	return stub
}

// attester serves a fake attestation-api whose verified self-report carries
// binding in whichever claim the platform uses. Both arms go through one code
// path now, so both are exercised by varying only the platform and the claim.
func attester(t *testing.T, platform teetypes.PlatformType, binding []byte) string {
	t.Helper()
	return stubAttester(t, selfReport{platform: platform, binding: binding}).URL
}

func tdxBinding(pub []byte) []byte { v := runtimemeasure.Seed(pub); return v[:] }
func snpBinding(pub []byte) []byte { v := runtimemeasure.HostData(pub); return v[:] }

// fill returns a 48-byte register value, every byte equal to b.
func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 48) }

// The happy path on both platforms: the staged pubkey is the one the launch
// bound, so the key is released. The caller no longer passes a platform — it
// comes from the verified report.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		binding  []byte
	}{
		{teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{teetypes.PlatformAzTDX, tdxBinding(operatorPub)},
		{teetypes.PlatformSNP, snpBinding(operatorPub)},
		{teetypes.PlatformGcpSNP, snpBinding(operatorPub)},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			url := attester(t, tc.platform, tc.binding)

			got, err := LoadMeasuredOperatorKey(context.Background(), url)
			if err != nil {
				t.Fatalf("LoadMeasuredOperatorKey: %v", err)
			}
			if string(got) != string(operatorPub) {
				t.Errorf("returned key = %q, want %q", got, operatorPub)
			}
		})
	}
}

// Every way the anchor check can fail must refuse. Releasing a key the launch
// did not bind is the vulnerability this check exists to prevent.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	otherKey := []byte("a different operator key")
	zeroTDX := make([]byte, runtimemeasure.Size)
	zeroSNP := make([]byte, runtimemeasure.HostDataSize)

	for _, tc := range []struct {
		name     string
		staged   []byte
		platform teetypes.PlatformType
		binding  []byte
	}{
		{"no staged pubkey", nil, teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{"empty staged pubkey", []byte{}, teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{"tdx: register holds another key's seed", operatorPub, teetypes.PlatformTDX, tdxBinding(otherKey)},
		{"tdx: keyless launch leaves the register zero", operatorPub, teetypes.PlatformTDX, zeroTDX},
		{"snp: HOSTDATA holds another key", operatorPub, teetypes.PlatformSNP, snpBinding(otherKey)},
		{"snp: keyless launch leaves HOSTDATA zero", operatorPub, teetypes.PlatformSNP, zeroSNP},
		// A TDX-width value in the SNP claim is MRCONFIGID, not HOSTDATA. It
		// must be refused by width, never truncated into a match.
		{"snp claim carrying a 48-byte value", operatorPub, teetypes.PlatformSNP, tdxBinding(operatorPub)},
		{"tdx claim carrying a 32-byte value", operatorPub, teetypes.PlatformTDX, snpBinding(operatorPub)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, tc.staged)
			url := attester(t, tc.platform, tc.binding)
			if _, err := LoadMeasuredOperatorKey(context.Background(), url); err == nil {
				t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
			}
		})
	}
}

// A missing pubkey is reported as ErrNoOperatorKey so a caller can tell a
// non-operator boot from every other refusal; an empty file is not.
func TestLoadMeasuredOperatorKeyClassifiesAbsence(t *testing.T) {
	stageOperatorPubkey(t, nil)
	_, err := LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1")
	if !errors.Is(err, ErrNoOperatorKey) {
		t.Errorf("err = %v, want errors.Is(..., ErrNoOperatorKey)", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, must not leak fs.ErrNotExist (a missing sysfs node would be mistaken for it)", err)
	}

	stageOperatorPubkey(t, []byte{})
	_, err = LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1")
	if err == nil || errors.Is(err, ErrNoOperatorKey) {
		t.Errorf("err = %v, want a refusal that is NOT ErrNoOperatorKey for an empty staged key", err)
	}
}

// An unreachable attestation-api is a refusal, not a fallback to the local
// register: the binding must come from a report whose signature was checked.
func TestLoadMeasuredOperatorKeyRefusesUnreachableAttester(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	if _, err := LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1"); err == nil {
		t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
	}
}

// A platform this build has no binding rules for gets no key.
func TestLoadMeasuredOperatorKeyRefusesUnknownPlatform(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	url := attester(t, "nonsense", tdxBinding(operatorPub))
	if _, err := LoadMeasuredOperatorKey(context.Background(), url); err == nil {
		t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
	}
}

// The self-report must be non-replayable: the code asks the verifier to bind a
// fresh nonce, and a stub reporting success without one would pass a replay.
func TestSelfReportBindsAFreshNonce(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	stub := testattest.New(t)
	stub.SetPlatform(types.Platform(teetypes.PlatformSNP))
	v := testattest.PassingVerdict("")
	v.Claims.InitData = snpBinding(operatorPub)
	stub.SetVerdict(v)

	if _, err := LoadMeasuredOperatorKey(context.Background(), stub.URL); err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("verify requests = %d, want 1", len(reqs))
	}
	sent := reqs[0].Params.ExpectedReportData
	if sent == nil || len(sent.Bytes()) == 0 {
		t.Fatal("no expected report data sent; a self-report with no nonce is replayable")
	}
	var zero [64]byte
	if string(sent.Bytes()) == string(zero[:len(sent.Bytes())]) {
		t.Fatal("expected report data is all zero, so it is not a fresh nonce")
	}
}

// The boot-order race: attestation-api is ordered before c8s-chart-values
// but binds its port only after fetching its certificate collateral, so the
// first /health calls fail. The self-report must wait for readiness and then
// attest exactly once.
func TestSelfReportWaitsForAttestationAPI(t *testing.T) {
	launchDigest := fill(0x5a)
	stub := stubAttester(t, selfReport{platform: teetypes.PlatformSNP, launchDigest: launchDigest})
	stub.SetHealthFailures(3)

	measurement, _, err := OwnLaunchMeasurement(context.Background(), "sev-snp", stub.URL)
	if err != nil {
		t.Fatalf("OwnLaunchMeasurement: %v", err)
	}
	if !bytes.Equal(measurement, launchDigest) {
		t.Errorf("measurement = %x, want %x", measurement, launchDigest)
	}
	if n := stub.HealthRequests(); n < 4 {
		t.Errorf("/health called %d times, want at least 4 (3 failures then success)", n)
	}
	if n := len(stub.AttestRequests()); n != 1 {
		t.Errorf("/attest called %d times, want exactly 1", n)
	}
}

func TestSelfReportFailsWhenAttestationAPINeverReady(t *testing.T) {
	_, _, err := OwnLaunchMeasurement(context.Background(), "sev-snp", "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("want an error when the attestation-api never answers /health")
	}
	if !strings.Contains(err.Error(), "not ready after") {
		t.Errorf("error = %v, want the readiness wait to report the timeout", err)
	}
}

// The own measurement comes off the verified report: MRTD plus RTMR[1]/[2]
// on TDX, LAUNCH_DIGEST alone on SNP.
func TestOwnLaunchMeasurement(t *testing.T) {
	t.Run("tdx", func(t *testing.T) {
		mrtd, rtmr1, rtmr2 := fill(0xaa), fill(0xbb), fill(0xcc)
		url := stubAttester(t, selfReport{platform: teetypes.PlatformTDX, launchDigest: mrtd, rtmr1: rtmr1, rtmr2: rtmr2}).URL

		measurement, rtmrs, err := OwnLaunchMeasurement(context.Background(), "tdx", url)
		if err != nil {
			t.Fatalf("OwnLaunchMeasurement: %v", err)
		}
		if !bytes.Equal(measurement, mrtd) {
			t.Errorf("measurement = %x, want mrtd %x", measurement, mrtd)
		}
		if !bytes.Equal(rtmrs[1], rtmr1) {
			t.Errorf("rtmrs[1] = %x, want %x", rtmrs[1], rtmr1)
		}
		if !bytes.Equal(rtmrs[2], rtmr2) {
			t.Errorf("rtmrs[2] = %x, want %x", rtmrs[2], rtmr2)
		}
		if len(rtmrs) != 2 {
			t.Errorf("rtmrs has %d entries, want exactly RTMR[1] and RTMR[2]", len(rtmrs))
		}
	})

	t.Run("snp", func(t *testing.T) {
		want := fill(0xab)
		url := stubAttester(t, selfReport{platform: teetypes.PlatformSNP, launchDigest: want}).URL

		measurement, rtmrs, err := OwnLaunchMeasurement(context.Background(), "sev-snp", url)
		if err != nil {
			t.Fatalf("OwnLaunchMeasurement: %v", err)
		}
		if !bytes.Equal(measurement, want) {
			t.Errorf("measurement = %x, want %x", measurement, want)
		}
		if rtmrs != nil {
			t.Errorf("rtmrs = %v, want nil (RTMRs are TDX-only)", rtmrs)
		}
	})
}

// A measurement that cannot be read exactly must not be pinned at all.
func TestOwnLaunchMeasurementFailsClosed(t *testing.T) {
	tdx := func(r selfReport) selfReport { r.platform = teetypes.PlatformTDX; return r }
	full := selfReport{launchDigest: fill(0xaa), rtmr1: fill(0xbb), rtmr2: fill(0xcc)}
	for _, tc := range []struct {
		name     string
		platform string
		report   selfReport
	}{
		{"snp: launch_digest wrong width", "sev-snp", selfReport{platform: teetypes.PlatformSNP, launchDigest: []byte{0xab}}},
		{"snp: launch_digest missing", "sev-snp", selfReport{platform: teetypes.PlatformSNP}},
		{"tdx: rtmr1 missing", "tdx", tdx(selfReport{launchDigest: full.launchDigest, rtmr2: full.rtmr2})},
		{"tdx: rtmr2 missing", "tdx", tdx(selfReport{launchDigest: full.launchDigest, rtmr1: full.rtmr1})},
		{"tdx: rtmr2 wrong width", "tdx", tdx(selfReport{launchDigest: full.launchDigest, rtmr1: full.rtmr1, rtmr2: []byte{1}})},
		// A chart baked for one TEE must never be pinned to the other's report.
		{"image built for tdx, report from snp", "tdx", selfReport{platform: teetypes.PlatformSNP, launchDigest: fill(0xab)}},
		{"image built for snp, report from tdx", "sev-snp", tdx(full)},
		{"unknown platform in the report", "tdx", selfReport{platform: "nonsense", launchDigest: fill(0xab)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := stubAttester(t, tc.report).URL
			if _, _, err := OwnLaunchMeasurement(context.Background(), tc.platform, url); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}

	t.Run("launch_digest not hex", func(t *testing.T) {
		stub := testattest.New(t)
		v := testattest.PassingVerdict("")
		v.Claims.LaunchDigest = "not-hex-zz"
		stub.SetVerdict(v)
		if _, _, err := OwnLaunchMeasurement(context.Background(), "sev-snp", stub.URL); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("unknown platform in config", func(t *testing.T) {
		url := stubAttester(t, selfReport{platform: teetypes.PlatformSNP, launchDigest: fill(0xab)}).URL
		if _, _, err := OwnLaunchMeasurement(context.Background(), "no-such-platform", url); err == nil {
			t.Fatal("want an error for an unknown platform")
		} else if !strings.Contains(err.Error(), "no-such-platform") {
			t.Errorf("error = %v, want it to name the platform", err)
		}
	})
}

// operatorReport is a self-report from a guest launched with operatorPub,
// carrying launchDigest and, on TDX, fixed RTMR pins.
func operatorReport(platform teetypes.PlatformType, launchDigest []byte) selfReport {
	r := selfReport{platform: platform, launchDigest: launchDigest}
	if platform.IsTDX() {
		r.binding, r.rtmr1, r.rtmr2 = tdxBinding(operatorPub), fill(0xbb), fill(0xcc)
	} else {
		r.binding = snpBinding(operatorPub)
	}
	return r
}

var combinedPlatforms = []struct {
	name     string
	platform teetypes.PlatformType
}{{"tdx", teetypes.PlatformTDX}, {"sev-snp", teetypes.PlatformSNP}}

// The combined loader answers both questions off one self-report: the guest
// attests itself once per boot, not once per check.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementAttestsOnce(t *testing.T) {
	for _, p := range combinedPlatforms {
		t.Run(p.name, func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			launchDigest := fill(0xab)
			stub := stubAttester(t, operatorReport(p.platform, launchDigest))

			gotPub, pubErr, gotMeasurement, gotRTMRs, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), p.name, stub.URL)
			if err != nil {
				t.Fatalf("LoadMeasuredOperatorKeyAndOwnMeasurement: %v", err)
			}
			if pubErr != nil {
				t.Fatalf("pubErr: %v", pubErr)
			}
			if string(gotPub) != string(operatorPub) {
				t.Errorf("pub = %q, want %q", gotPub, operatorPub)
			}
			if !bytes.Equal(gotMeasurement, launchDigest) {
				t.Errorf("measurement = %x, want %x", gotMeasurement, launchDigest)
			}
			if (gotRTMRs != nil) != p.platform.IsTDX() {
				t.Errorf("rtmrs = %v; want them on TDX only", gotRTMRs)
			}
			if n := len(stub.AttestRequests()); n != 1 {
				t.Errorf("attest-api /attest called %d times, want exactly 1 (one self-report shared by both checks)", n)
			}
			if n := len(stub.VerifyRequests()); n != 1 {
				t.Errorf("attest-api /verify called %d times, want exactly 1", n)
			}
		})
	}
}

// A launch with no opkeydata pubkey at all: the own measurement must still
// resolve (bootDerivedValues needs it regardless of the operator key), and
// pubErr must wrap ErrNoOperatorKey rather than failing the whole call.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementNonOperatorBoot(t *testing.T) {
	for _, p := range combinedPlatforms {
		t.Run(p.name, func(t *testing.T) {
			stageOperatorPubkey(t, nil)
			launchDigest := fill(0xcd)
			r := operatorReport(p.platform, launchDigest)
			r.binding = make([]byte, len(r.binding)) // keyless launch: zero binding
			url := stubAttester(t, r).URL

			pub, pubErr, measurement, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), p.name, url)
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			if !errors.Is(pubErr, ErrNoOperatorKey) {
				t.Errorf("pubErr = %v, want errors.Is(..., ErrNoOperatorKey)", pubErr)
			}
			if pub != nil {
				t.Errorf("pub = %v, want nil", pub)
			}
			if !bytes.Equal(measurement, launchDigest) {
				t.Errorf("measurement = %x, want %x — own measurement must resolve on a non-operator boot too", measurement, launchDigest)
			}
		})
	}
}

// A staged pubkey the launch did not bind: pubErr must carry the mismatch
// (not ErrNoOperatorKey), while the own measurement still resolves from the
// one self-report already made.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementSubstitutedKey(t *testing.T) {
	for _, p := range combinedPlatforms {
		t.Run(p.name, func(t *testing.T) {
			stageOperatorPubkey(t, []byte("a different key the host swapped in"))
			launchDigest := fill(0xef)
			url := stubAttester(t, operatorReport(p.platform, launchDigest)).URL

			gotPub, pubErr, measurement, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), p.name, url)
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			if pubErr == nil {
				t.Fatal("want pubErr set for a binding mismatch")
			}
			if errors.Is(pubErr, ErrNoOperatorKey) {
				t.Errorf("pubErr = %v, must NOT be classified as absent (a substituted key must fail closed)", pubErr)
			}
			if gotPub != nil {
				t.Errorf("pub = %v, want nil", gotPub)
			}
			if !bytes.Equal(measurement, launchDigest) {
				t.Errorf("measurement = %x, want %x", measurement, launchDigest)
			}
		})
	}
}

// The hard-fail path: this guest's own measurement cannot be resolved, which
// must fail the whole call even though a valid operator key was staged.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementFailsClosedOnUnresolvableMeasurement(t *testing.T) {
	t.Run("tdx report missing a register", func(t *testing.T) {
		stageOperatorPubkey(t, operatorPub)
		r := operatorReport(teetypes.PlatformTDX, fill(0xaa))
		r.rtmr2 = nil
		url := stubAttester(t, r).URL
		if _, _, _, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "tdx", url); err == nil {
			t.Fatal("want an error when this guest's own launch measurement cannot be resolved")
		}
	})

	t.Run("attestation-api unreachable", func(t *testing.T) {
		stageOperatorPubkey(t, operatorPub)
		if _, _, _, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "sev-snp", "http://127.0.0.1:1"); err == nil {
			t.Fatal("want an error when the attestation-api is unreachable")
		}
	})
}
