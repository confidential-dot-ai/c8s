package verify

import (
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

func TestExpectedRTMR3PinUnset(t *testing.T) {
	got, err := expectedRTMR3Pin(config{})
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

	fromKey, err := expectedRTMR3Pin(config{operatorKeyFile: keyPath})
	if err != nil {
		t.Fatalf("--operator-key: %v", err)
	}
	fromHex, err := expectedRTMR3Pin(config{expectedRTMR3Hex: hex.EncodeToString(fromKey)})
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

	a, err := expectedRTMR3Pin(config{operatorKeyFile: withNewline})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := expectedRTMR3Pin(config{operatorKeyFile: without})
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
			got, err := expectedRTMR3Pin(tc.cfg)
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
