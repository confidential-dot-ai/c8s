package runtimemeasure

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	mrtdHex  = strings.Repeat("1a", Size)
	rtmr1Hex = strings.Repeat("2b", Size)
	rtmr2Hex = strings.Repeat("3c", Size)
)

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadImageManifestValid(t *testing.T) {
	// Extra unknown fields are allowed: build manifests carry other data.
	p := writeManifest(t, `{
		"schema": 3, "artifacts": {"kernel": "deadbeef"},
		"mrtd": "`+mrtdHex+`",
		"rtmr1": "`+rtmr1Hex+`",
		"rtmr2": "`+rtmr2Hex+`"
	}`)
	pins, err := LoadImageManifest(p)
	if err != nil {
		t.Fatalf("LoadImageManifest: %v", err)
	}
	for _, reg := range []struct {
		name string
		got  [Size]byte
		want string
	}{
		{"mrtd", pins.MRTD, mrtdHex},
		{"rtmr1", pins.RTMR1, rtmr1Hex},
		{"rtmr2", pins.RTMR2, rtmr2Hex},
	} {
		if hex.EncodeToString(reg.got[:]) != reg.want {
			t.Errorf("%s = %x, want %s", reg.name, reg.got, reg.want)
		}
	}
}

func TestLoadImageManifestRejects(t *testing.T) {
	for _, tc := range []struct{ name, content, wantErr string }{
		{"not json", "not json at all", "not a JSON object"},
		{"json array", `[1,2,3]`, "not a JSON object"},
		{"missing mrtd",
			`{"rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`missing "mrtd"`},
		{"missing rtmr1",
			`{"mrtd":"` + mrtdHex + `","rtmr2":"` + rtmr2Hex + `"}`,
			`missing "rtmr1"`},
		{"missing rtmr2",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `"}`,
			`missing "rtmr2"`},
		{"generic artifact-hash manifest",
			`{"files":{"disk.img":"sha256:abc"}}`,
			"a generic artifact-hash manifest.json is not it"},
		{"bad hex",
			`{"mrtd":"` + strings.Repeat("zz", Size) + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			"lowercase hex"},
		{"uppercase hex",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + strings.ToUpper(rtmr1Hex) + `","rtmr2":"` + rtmr2Hex + `"}`,
			"lowercase hex"},
		{"wrong length",
			`{"mrtd":"` + mrtdHex + `","rtmr1":"` + rtmr1Hex + `","rtmr2":"aabb"}`,
			"want 96"},
		{"wrong json type", `{"mrtd":7,"rtmr1":"` + rtmr1Hex + `","rtmr2":"` + rtmr2Hex + `"}`,
			"not a JSON object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadImageManifest(writeManifest(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// One malformed field must fail the whole load: a partial pin (say MRTD
// without RTMR[2]) would silently verify only part of the image.
func TestLoadImageManifestIsAtomic(t *testing.T) {
	p := writeManifest(t, `{"mrtd":"`+mrtdHex+`","rtmr1":"`+rtmr1Hex+`","rtmr2":"bad"}`)
	pins, err := LoadImageManifest(p)
	if err == nil {
		t.Fatal("want error")
	}
	if pins != (ImagePins{}) {
		t.Error("a failed load must not return partial pins")
	}
}

func TestLoadImageManifestMissingFile(t *testing.T) {
	_, err := LoadImageManifest(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "read image manifest") {
		t.Errorf("error = %v, want a read error", err)
	}
}
