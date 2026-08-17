package tdxmeasure

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	gcetdx "github.com/google/gce-tcb-verifier/tdx"
)

// tdvfPath is where kata-qemu-tdx's `firmware` key points on a c8s node.
const tdvfPath = "/opt/kata/share/ovmf/OVMF.inteltdx.fd"

const (
	// wantMRTD was captured on 2026-08-03 from two live kata-qemu-tdx pods of
	// different vCPU shapes (1 and 2 vCPU) on b300-node-2, read from each
	// pod's own attestation report via the in-guest attestation-service. Both
	// reported this same value.
	wantMRTD = "c78e2b8b2f66207f3807d8d999f51e04f5eab8f7aa02614a86ddd81b61f4e79c" +
		"5d7616664fcb190b8eaae2e26d60b12a"
	// wantTDVFSHA is the TDVF build that produced wantMRTD.
	wantTDVFSHA = "2af9e5e974c0dc201163d1fd419f234cc4b6e64e99425ce6619e9a077fb0c0b6"
)

// loadTDVF returns the validated TDVF build, or skips. The 4 MiB image is not
// committed: CI's tripwire job fetches the pinned TDVF and sets C8S_TDVF;
// elsewhere this runs on a TDX node (or with C8S_TDVF set) and skips
// otherwise. See docs/kata-launch-measurement.md to re-capture the expected
// value.
func loadTDVF(t *testing.T) []byte {
	t.Helper()
	p := tdvfPath
	if env := os.Getenv("C8S_TDVF"); env != "" {
		p = env
	}
	fw, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("TDVF not present (%v); set C8S_TDVF to run this check", err)
	}
	if sum := sha256.Sum256(fw); hex.EncodeToString(sum[:]) != wantTDVFSHA {
		t.Skipf("TDVF at %s is not the validated build (sha256 %x)", p, sum)
	}
	return fw
}

// TestMRTDMatchesHardware is the load-bearing test: the value c8s would pin
// must equal the one real TDX silicon reported. It is also the tripwire for a
// change in the upstream library's default LaunchOptions, which would silently
// move the pinned measurement.
func TestMRTDMatchesHardware(t *testing.T) {
	got, err := MRTD(loadTDVF(t))
	if err != nil {
		t.Fatalf("MRTD: %v", err)
	}
	if len(got) != DigestLen {
		t.Fatalf("MRTD length = %d, want %d", len(got), DigestLen)
	}
	if hex.EncodeToString(got) != wantMRTD {
		t.Errorf("MRTD = %s\nwant  = %s", hex.EncodeToString(got), wantMRTD)
	}
}

// TestOtherLaunchOptionsAreWrong pins WHY launchOptions picks the plain
// default. Both other presets model a Google hypervisor and produce a digest
// that no kata pod would ever report; pinning one would refuse every pod. If
// upstream ever makes them equivalent this test fails and the comment in
// launchOptions needs revisiting.
func TestOtherLaunchOptionsAreWrong(t *testing.T) {
	fw := loadTDVF(t)

	unaccepted := gcetdx.LaunchOptionsDefault("")
	unaccepted.DisableUnacceptedMemory = true //nolint:staticcheck // deprecated upstream; still the preset this test rules out.

	for name, opts := range map[string]*gcetdx.LaunchOptions{
		"TDHOBBug":                gcetdx.LaunchOptionsDefaultTDHOBBug(""),
		"DisableUnacceptedMemory": unaccepted,
	} {
		d, err := gcetdx.MRTD(opts, fw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hex.EncodeToString(d[:]) == wantMRTD {
			t.Errorf("%s now matches hardware; launchOptions() rationale is stale", name)
		}
	}
}

// TestMRTDIsFirmwareOnly: the signature takes firmware and nothing else, so a
// caller cannot accidentally feed a pod shape in. Same bytes, same digest.
func TestMRTDIsFirmwareOnly(t *testing.T) {
	fw := loadTDVF(t)
	a, err := MRTD(fw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MRTD(fw)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatalf("MRTD not deterministic: %x vs %x", a, b)
	}
}

func TestMRTDRejectsGarbage(t *testing.T) {
	for name, fw := range map[string][]byte{
		"empty":       {},
		"no metadata": make([]byte, 4096),
	} {
		if _, err := MRTD(fw); err == nil {
			t.Errorf("%s: MRTD accepted a non-TDVF image", name)
		}
	}
}
