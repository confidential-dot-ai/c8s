package credrelease

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// overrideTDXGuestSysfsDir points tdxGuestSysfsDir at a temp dir for the
// duration of the test, mirroring overrideBindingPaths.
func overrideTDXGuestSysfsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := tdxGuestSysfsDir
	tdxGuestSysfsDir = dir
	t.Cleanup(func() { tdxGuestSysfsDir = orig })
	return dir
}

// writeRegister writes a 48-byte register file <dir>/<name>:sha384, every
// byte equal to fill.
func writeRegister(t *testing.T, dir, name string, fill byte) []byte {
	t.Helper()
	b := bytes.Repeat([]byte{fill}, 48)
	writeFileT(t, filepath.Join(dir, name+":sha384"), b)
	return b
}

func TestOwnLaunchMeasurementTDX(t *testing.T) {
	dir := overrideTDXGuestSysfsDir(t)
	mrtd := writeRegister(t, dir, "mrtd", 0xaa)
	rtmr1 := writeRegister(t, dir, "rtmr1", 0xbb)
	rtmr2 := writeRegister(t, dir, "rtmr2", 0xcc)

	measurement, rtmrs, err := OwnLaunchMeasurement(context.Background(), "tdx", "")
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
}

func TestOwnLaunchMeasurementTDXFailsClosedOnMissingRegister(t *testing.T) {
	dir := overrideTDXGuestSysfsDir(t)
	writeRegister(t, dir, "mrtd", 0xaa)
	// rtmr1/rtmr2 deliberately absent.

	if _, _, err := OwnLaunchMeasurement(context.Background(), "tdx", ""); err == nil {
		t.Fatal("want an error when a runtime measurement register is missing")
	}
}

// snpLaunchDigestAttester returns the URL of a stub attestation-api whose
// verified claims report launchDigestHex as launch_digest.
func snpLaunchDigestAttester(t *testing.T, launchDigestHex string) string {
	t.Helper()
	stub := testattest.New(t)
	v := testattest.PassingVerdict(launchDigestHex)
	stub.SetVerdict(v)
	return stub.URL
}

func TestOwnLaunchMeasurementSNP(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, 48)
	url := snpLaunchDigestAttester(t, hex.EncodeToString(want))

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
}

func TestOwnLaunchMeasurementSNPFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		url  func(t *testing.T) string
	}{
		{
			name: "launch_digest wrong width",
			url:  func(t *testing.T) string { return snpLaunchDigestAttester(t, "ab") },
		},
		{
			name: "launch_digest not hex",
			url: func(t *testing.T) string {
				stub := testattest.New(t)
				v := testattest.PassingVerdict("")
				v.Claims.LaunchDigest = "not-hex-zz"
				stub.SetVerdict(v)
				return stub.URL
			},
		},
		{
			name: "attestation-api unreachable",
			url:  func(t *testing.T) string { return "http://127.0.0.1:1" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := OwnLaunchMeasurement(context.Background(), "sev-snp", tc.url(t)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestOwnLaunchMeasurementUnknownPlatform(t *testing.T) {
	if _, _, err := OwnLaunchMeasurement(context.Background(), "no-such-platform", ""); err == nil {
		t.Fatal("want an error for an unknown platform")
	} else if !strings.Contains(err.Error(), "no-such-platform") {
		t.Errorf("error = %v, want it to name the platform", err)
	}
}

// overrideBindingPaths points the package's sysfs/staging paths at files under
// a temp dir for the duration of the test. The files do not exist yet; each
// test writes what its scenario needs.
func overrideBindingPaths(t *testing.T) (pubPath, rtmrPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "operator-pubkey")
	rtmrPath = filepath.Join(dir, "rtmr3")
	origPub, origRTMR := operatorPubkeyPath, rtmr3SysfsPath
	operatorPubkeyPath, rtmr3SysfsPath = pubPath, rtmrPath
	t.Cleanup(func() { operatorPubkeyPath, rtmr3SysfsPath = origPub, origRTMR })
	return pubPath, rtmrPath
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// expectedRTMR3ForKey adapts runtimemeasure.ForOperatorKey for the sysfs
// fixtures the binding tests write. The formula and hardware vectors are
// pinned in pkg/runtimemeasure.
func expectedRTMR3ForKey(pub []byte) []byte {
	v := runtimemeasure.ForOperatorKey(pub)
	return v[:]
}

// TestLoadMeasuredOperatorKey covers the happy path: the staged pubkey matches
// the (fake) RTMR[3] the initrd would have extended, so the key is released.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	pubPath, rtmrPath := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)
	writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))

	got, err := LoadMeasuredOperatorKey(context.Background(), "tdx", "")
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}
}

// TestLoadMeasuredOperatorKeyFailsClosed enumerates the ways the anchor check
// must refuse: substituted key, malformed or missing RTMR, missing/empty key.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	pub := []byte("operator public key bytes")
	tests := []struct {
		name  string
		stage func(t *testing.T, pubPath, rtmrPath string)
	}{
		{
			name: "substituted pubkey",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, []byte("a different key the host swapped in"))
				writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))
			},
		},
		{
			name: "rtmr wrong length",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
				writeFileT(t, rtmrPath, make([]byte, 47))
			},
		},
		{
			name: "rtmr missing",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
			},
		},
		{
			name:  "pubkey missing",
			stage: func(t *testing.T, pubPath, rtmrPath string) {},
		},
		{
			name: "pubkey empty",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, nil)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubPath, rtmrPath := overrideBindingPaths(t)
			tc.stage(t, pubPath, rtmrPath)
			if _, err := LoadMeasuredOperatorKey(context.Background(), "tdx", ""); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// snpAttester returns the URL of a stub attestation-api whose verified claims
// report initData verbatim as this guest's HOSTDATA.
func snpAttester(t *testing.T, initData []byte) string {
	t.Helper()
	stub := testattest.New(t)
	v := testattest.PassingVerdict("")
	v.Claims.InitData = initData
	stub.SetVerdict(v)
	return stub.URL
}

// TestLoadMeasuredOperatorKeySNP covers the SNP happy path: the verified
// self-report's HOSTDATA equals sha256 of the staged pubkey bytes.
func TestLoadMeasuredOperatorKeySNP(t *testing.T) {
	pubPath, _ := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)
	want := runtimemeasure.HostDataForOperatorKey(pub)
	url := snpAttester(t, want[:])

	got, err := LoadMeasuredOperatorKey(context.Background(), "sev-snp", url)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}
}

// TestLoadMeasuredOperatorKeySNPFailsClosed enumerates the SNP refusals:
// keyless launch (zero HOSTDATA), a different key's HOSTDATA, TDX-shaped and
// malformed claims, an unreachable attestation-api, an unknown platform.
func TestLoadMeasuredOperatorKeySNPFailsClosed(t *testing.T) {
	pub := []byte("operator public key bytes")
	otherKey := runtimemeasure.HostDataForOperatorKey([]byte("a different operator key"))
	tests := []struct {
		name     string
		platform string
		url      func(t *testing.T) string
	}{
		{
			name:     "keyless launch: zero HOSTDATA",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				return snpAttester(t, bytes.Repeat([]byte{0}, runtimemeasure.HostDataSize))
			},
		},
		{
			name:     "launched for a different key",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, otherKey[:]) },
		},
		{
			name:     "TDX-sized InitData (48-byte MRCONFIGID)",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				return snpAttester(t, bytes.Repeat([]byte{0xa5}, 48))
			},
		},
		{
			// The wire's not-hex shape is refused by the HexBytes decoder in
			// the client; through the typed stub only widths are expressible.
			name:     "InitData wrong width",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, []byte("zz")) },
		},
		{
			name:     "InitData claim empty",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return snpAttester(t, nil) },
		},
		// The two verdict cases carry a MATCHING InitData: refusal must come
		// from verdict enforcement, not the claims compare, so a refactor
		// that drops VerifyEvidence's enforcement fails here.
		{
			name:     "verifier refuses: signature invalid",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				want := runtimemeasure.HostDataForOperatorKey(pub)
				stub := testattest.New(t)
				v := testattest.PassingVerdict("")
				v.SignatureValid = false
				v.Claims.InitData = want[:]
				stub.SetVerdict(v)
				return stub.URL
			},
		},
		{
			name:     "verifier refuses: REPORTDATA not bound",
			platform: "sev-snp",
			url: func(t *testing.T) string {
				want := runtimemeasure.HostDataForOperatorKey(pub)
				stub := testattest.New(t)
				v := testattest.PassingVerdict("")
				v.ReportDataMatch = nil
				v.Claims.InitData = want[:]
				stub.SetVerdict(v)
				return stub.URL
			},
		},
		{
			name:     "attestation-api unreachable",
			platform: "sev-snp",
			url:      func(t *testing.T) string { return "http://127.0.0.1:1" },
		},
		{
			name:     "unknown platform has no binding check",
			platform: "no-such-platform",
			url:      func(t *testing.T) string { return "" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubPath, _ := overrideBindingPaths(t)
			writeFileT(t, pubPath, pub)
			if _, err := LoadMeasuredOperatorKey(context.Background(), tc.platform, tc.url(t)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestLoadMeasuredOperatorKeyAndOwnMeasurementSNPAttestsOnce is the point of
// the combined entry point: on SNP it must self-attest exactly once and use
// that one verified report for both the operator-key HOSTDATA check and the
// launch-digest read, not attest twice (once per check) the way calling
// LoadMeasuredOperatorKey and OwnLaunchMeasurement separately would.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementSNPAttestsOnce(t *testing.T) {
	pubPath, _ := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)

	hostData := runtimemeasure.HostDataForOperatorKey(pub)
	launchDigest := bytes.Repeat([]byte{0xab}, 48)
	stub := testattest.New(t)
	v := testattest.PassingVerdict(hex.EncodeToString(launchDigest))
	v.Claims.InitData = hostData[:]
	stub.SetVerdict(v)

	gotPub, pubErr, gotMeasurement, gotRTMRs, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "sev-snp", stub.URL)
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKeyAndOwnMeasurement: %v", err)
	}
	if pubErr != nil {
		t.Fatalf("pubErr: %v", pubErr)
	}
	if string(gotPub) != string(pub) {
		t.Errorf("pub = %q, want %q", gotPub, pub)
	}
	if !bytes.Equal(gotMeasurement, launchDigest) {
		t.Errorf("measurement = %x, want %x", gotMeasurement, launchDigest)
	}
	if gotRTMRs != nil {
		t.Errorf("rtmrs = %v, want nil on SNP", gotRTMRs)
	}
	if n := len(stub.AttestRequests()); n != 1 {
		t.Errorf("attest-api /attest called %d times, want exactly 1 (one self-report shared by both checks)", n)
	}
	if n := len(stub.VerifyRequests()); n != 1 {
		t.Errorf("attest-api /verify called %d times, want exactly 1", n)
	}
}

// TestLoadMeasuredOperatorKeyAndOwnMeasurementNonOperatorBoot covers a launch
// with no opkeydata pubkey at all: the own measurement must still resolve
// (bootDerivedValues needs it regardless of the operator key), and pubErr
// must carry the fs.ErrNotExist chain rather than failing the whole call.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementNonOperatorBoot(t *testing.T) {
	t.Run("tdx", func(t *testing.T) {
		overrideBindingPaths(t) // pubkey path left unwritten
		dir := overrideTDXGuestSysfsDir(t)
		mrtd := writeRegister(t, dir, "mrtd", 0xaa)
		writeRegister(t, dir, "rtmr1", 0xbb)
		writeRegister(t, dir, "rtmr2", 0xcc)

		pub, pubErr, measurement, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "tdx", "")
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if pubErr == nil {
			t.Fatal("want pubErr set (no pubkey staged)")
		}
		if !errors.Is(pubErr, fs.ErrNotExist) {
			t.Errorf("pubErr = %v, want errors.Is(..., fs.ErrNotExist)", pubErr)
		}
		if pub != nil {
			t.Errorf("pub = %v, want nil", pub)
		}
		if !bytes.Equal(measurement, mrtd) {
			t.Errorf("measurement = %x, want mrtd %x — own measurement must resolve on a non-operator boot too", measurement, mrtd)
		}
	})

	t.Run("snp", func(t *testing.T) {
		overrideBindingPaths(t) // pubkey path left unwritten
		launchDigest := bytes.Repeat([]byte{0xcd}, 48)
		url := snpLaunchDigestAttester(t, hex.EncodeToString(launchDigest))

		pub, pubErr, measurement, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "sev-snp", url)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if !errors.Is(pubErr, fs.ErrNotExist) {
			t.Errorf("pubErr = %v, want errors.Is(..., fs.ErrNotExist)", pubErr)
		}
		if pub != nil {
			t.Errorf("pub = %v, want nil", pub)
		}
		if !bytes.Equal(measurement, launchDigest) {
			t.Errorf("measurement = %x, want %x — own measurement must resolve on a non-operator boot too", measurement, launchDigest)
		}
	})
}

// TestLoadMeasuredOperatorKeyAndOwnMeasurementSNPSubstitutedKey covers a
// staged pubkey that does not match launch-committed HOSTDATA: pubErr must
// carry the mismatch (not fs.ErrNotExist), while the own measurement still
// resolves from the one self-report already made.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementSNPSubstitutedKey(t *testing.T) {
	pubPath, _ := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)

	launchDigest := bytes.Repeat([]byte{0xef}, 48)
	stub := testattest.New(t)
	v := testattest.PassingVerdict(hex.EncodeToString(launchDigest))
	v.Claims.InitData = bytes.Repeat([]byte{0}, runtimemeasure.HostDataSize) // does not match pub
	stub.SetVerdict(v)

	gotPub, pubErr, measurement, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "sev-snp", stub.URL)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if pubErr == nil {
		t.Fatal("want pubErr set for a HOSTDATA mismatch")
	}
	if errors.Is(pubErr, fs.ErrNotExist) {
		t.Errorf("pubErr = %v, must NOT be classified as absent (a substituted key must fail closed)", pubErr)
	}
	if gotPub != nil {
		t.Errorf("pub = %v, want nil", gotPub)
	}
	if !bytes.Equal(measurement, launchDigest) {
		t.Errorf("measurement = %x, want %x", measurement, launchDigest)
	}
}

// TestLoadMeasuredOperatorKeyAndOwnMeasurementFailsClosedOnUnresolvableMeasurement
// covers the hard-fail path: this guest's own measurement itself cannot be
// read, which must fail the whole call even though a valid operator key was
// staged.
func TestLoadMeasuredOperatorKeyAndOwnMeasurementFailsClosedOnUnresolvableMeasurement(t *testing.T) {
	t.Run("tdx", func(t *testing.T) {
		pubPath, rtmrPath := overrideBindingPaths(t)
		pub := []byte("operator public key bytes")
		writeFileT(t, pubPath, pub)
		writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))
		overrideTDXGuestSysfsDir(t) // left empty: mrtd/rtmr1/rtmr2 absent

		if _, _, _, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "tdx", ""); err == nil {
			t.Fatal("want an error when this guest's own launch measurement cannot be resolved")
		}
	})

	t.Run("snp", func(t *testing.T) {
		pubPath, _ := overrideBindingPaths(t)
		pub := []byte("operator public key bytes")
		writeFileT(t, pubPath, pub)

		if _, _, _, _, err := LoadMeasuredOperatorKeyAndOwnMeasurement(context.Background(), "sev-snp", "http://127.0.0.1:1"); err == nil {
			t.Fatal("want an error when the attestation-api is unreachable")
		}
	})
}
