package verify

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// A real P-256 public key in the exact shape `openssl ec -pubout` emits,
// trailing newline included — the byte layout the initrd hashes.
const testOperatorPubPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtO+wEJtA/q+o7spl3iXUdzT9pLY/
Ln7t8a7OvDkCwGUhGYtOC2MGQ08BTMRqi2Q306MP5Xh9TnKAf0I/5QOglA==
-----END PUBLIC KEY-----
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// pin3 is the RTMR[3] slot of expectedRTMRPins, which is what the operator-key
// flags resolve into.
func pin3(t *testing.T, cfg config) ([]byte, error) {
	t.Helper()
	pins, _, err := expectedRTMRPins(cfg)
	return pins[3], err
}

func TestExpectedRTMR3PinUnset(t *testing.T) {
	got, err := pin3(t, config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("no flags must yield no pin, got %x", got)
	}
}

// The two spellings must agree, or an operator and a relying party pinning the
// same cluster would reach different verdicts.
func TestExpectedRTMR3PinSpellingsAgree(t *testing.T) {
	keyPath := writeTemp(t, "op.pub", testOperatorPubPEM)

	fromKey, err := pin3(t, config{operatorKeyFile: keyPath})
	if err != nil {
		t.Fatalf("--operator-key: %v", err)
	}
	fromHex, err := pin3(t, config{expectedRTMR3Hex: hex.EncodeToString(fromKey)})
	if err != nil {
		t.Fatalf("--expected-rtmr3: %v", err)
	}
	if string(fromKey) != string(fromHex) {
		t.Errorf("--operator-key and --expected-rtmr3 disagree: %x vs %x", fromKey, fromHex)
	}

	want := runtimemeasure.ForOperatorKey([]byte(testOperatorPubPEM))
	if string(fromKey) != string(want[:]) {
		t.Errorf("pin = %x, want ForOperatorKey = %x", fromKey, want)
	}
}

// The initrd hashes the file verbatim, so the CLI must not normalize it.
func TestExpectedRTMR3PinDoesNotNormalizePEM(t *testing.T) {
	withNewline := writeTemp(t, "a.pub", testOperatorPubPEM)
	without := writeTemp(t, "b.pub", strings.TrimRight(testOperatorPubPEM, "\n"))

	a, err := pin3(t, config{operatorKeyFile: withNewline})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := pin3(t, config{operatorKeyFile: without})
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if string(a) == string(b) {
		t.Error("a stripped trailing newline must change the pin; the CLI is normalizing the PEM")
	}
}

func TestExpectedRTMR3PinRejects(t *testing.T) {
	keyPath := writeTemp(t, "op.pub", testOperatorPubPEM)

	for _, tc := range []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			"both spellings at once",
			config{expectedRTMR3Hex: strings.Repeat("ab", 48), operatorKeyFile: keyPath},
			"mutually exclusive",
		},
		{"not hex", config{expectedRTMR3Hex: strings.Repeat("zz", 48)}, "not hex"},
		{"too short", config{expectedRTMR3Hex: "deadbeef"}, "want 48"},
		{"too long", config{expectedRTMR3Hex: strings.Repeat("ab", 64)}, "want 48"},
		{"missing file", config{operatorKeyFile: filepath.Join(t.TempDir(), "nope.pub")}, "read --operator-key"},
		{"empty file", config{operatorKeyFile: writeTemp(t, "empty.pub", "")}, "is empty"},
		{
			// A private key derives a pin that can never match, and the failure
			// would read as a compromised node rather than operator error.
			"private key by mistake",
			config{operatorKeyFile: writeTemp(t, "op.key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")},
			"looks like a PRIVATE key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pin3(t, tc.cfg)
			if err == nil {
				t.Fatalf("expected an error, got pin %x", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("a rejected pin must return nil, got %x", got)
			}
		})
	}
}

// A confos manifest as published alongside a c8s guest image. These are the
// real values for c8s-base:rke2-3ace878 — note the MRTD is IDENTICAL to the one
// in :rke2-c61839c below despite a different kernel and rootfs, because MRTD
// covers only the TDVF firmware's measured regions. That is exactly why
// RTMR[1]/RTMR[2] have to be pinned as well.
const manifest3ace878 = `{"tdx":{
  "mrtd":"9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
  "rtmr1":"a9420a2b2c3def741f5776790fc2d9a7d9da6cca8b709c19c36e317a05a54092ac6bf08c95ac07f068be2a590b93ce83",
  "rtmr2":"5cb4dabcc4471bf16032896d73a82e20f0ac7ba62da390db1b93b1b7c805557a20bc0c271862ec58ccf0a03be5369f16"}}`

const manifestC61839c = `{"tdx":{
  "mrtd":"9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
  "rtmr1":"7d45b1fe2b82b2bac087dd554c75b7f4cf3eacb567423afa92753b62dfb20611340840f2dd9ba0f7855de8ca5bdd2ab9",
  "rtmr2":"5dc5581a23b2a2772adf8a80bd91c5bdeecc775a310355bc7cce8aa5cac102b741e9b977f4232bb82fe9e642712afea7"}}`

func TestImageManifestPinsAllThreeRegisters(t *testing.T) {
	p := writeTemp(t, "manifest.json", manifest3ace878)
	pins, mrtd, err := expectedRTMRPins(config{imageManifest: p})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(mrtd) != "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1" {
		t.Errorf("mrtd = %x", mrtd)
	}
	if len(pins[1]) != 48 || len(pins[2]) != 48 {
		t.Errorf("rtmr1/rtmr2 not pinned: %d/%d bytes", len(pins[1]), len(pins[2]))
	}
	if pins[0] != nil || pins[3] != nil {
		t.Error("the manifest must not pin RTMR[0] or RTMR[3] — those are not image properties")
	}
}

// The load-bearing regression: two different guest images share an MRTD, so a
// measurement pin alone cannot tell them apart. If this ever stops being true,
// the extra registers are still correct — but the gap this closes is real today.
func TestMRTDAloneDoesNotDistinguishImages(t *testing.T) {
	a, mrtdA, err := expectedRTMRPins(config{imageManifest: writeTemp(t, "a.json", manifest3ace878)})
	if err != nil {
		t.Fatal(err)
	}
	b, mrtdB, err := expectedRTMRPins(config{imageManifest: writeTemp(t, "b.json", manifestC61839c)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mrtdA, mrtdB) {
		t.Skip("MRTDs now differ between these two images; the pin below is what matters regardless")
	}
	if bytes.Equal(a[1], b[1]) && bytes.Equal(a[2], b[2]) {
		t.Fatal("two different guest images produced identical RTMR[1] and RTMR[2] — the image pin distinguishes nothing")
	}
}

func TestImageManifestRejects(t *testing.T) {
	for _, tc := range []struct{ name, content, wantErr string }{
		{"not json", "not json at all", "not a confos manifest"},
		{"no tdx block", `{"build":{}}`, "missing tdx.mrtd"},
		{"partial", `{"tdx":{"mrtd":"aa"}}`, "missing tdx.mrtd"},
		{"bad hex", `{"tdx":{"mrtd":"zz","rtmr1":"aa","rtmr2":"bb"}}`, "not hex"},
		{"short digest", `{"tdx":{"mrtd":"aabb","rtmr1":"aabb","rtmr2":"aabb"}}`, "want 48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := expectedRTMRPins(config{imageManifest: writeTemp(t, "m.json", tc.content)})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// --image-manifest and the individual flags pin the same registers; taking both
// would leave it ambiguous which won.
func TestImageManifestConflictsWithIndividualFlags(t *testing.T) {
	p := writeTemp(t, "manifest.json", manifest3ace878)
	for _, cfg := range []config{
		{imageManifest: p, expectedRTMR1Hex: strings.Repeat("ab", 48)},
		{imageManifest: p, expectedRTMR2Hex: strings.Repeat("ab", 48)},
	} {
		if _, _, err := expectedRTMRPins(cfg); err == nil ||
			!strings.Contains(err.Error(), "already pins") {
			t.Errorf("error = %v, want a conflict", err)
		}
	}
}

// RTMR[3] is deployment identity, not image identity, so it composes with
// --image-manifest rather than conflicting with it.
func TestImageManifestComposesWithOperatorKey(t *testing.T) {
	pins, mrtd, err := expectedRTMRPins(config{
		imageManifest:   writeTemp(t, "manifest.json", manifest3ace878),
		operatorKeyFile: writeTemp(t, "op.pub", testOperatorPubPEM),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mrtd == nil || pins[1] == nil || pins[2] == nil || pins[3] == nil {
		t.Error("image manifest and operator key must pin MRTD + RTMR[1..3] together")
	}
}
