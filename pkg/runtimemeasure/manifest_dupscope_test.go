package runtimemeasure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A repeated "tdx" object must fail the load. encoding/json keeps the last
// occurrence, so a check that stopped at the first would validate registers
// the pin never loads.
func TestLoadImageManifestRejectsDuplicateTDXObject(t *testing.T) {
	published := strings.Repeat("a", 96)
	attacker := strings.Repeat("b", 96)
	doc := `{"tdx":{"mrtd":"` + published + `","rtmr1":"` + published + `","rtmr2":"` + published + `"},` +
		`"tdx":{"mrtd":"` + attacker + `","rtmr1":"` + attacker + `","rtmr2":"` + attacker + `"}}`

	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	pins, err := LoadImageManifest(path)
	if err == nil {
		t.Fatalf("loaded a manifest with two tdx objects: %x", pins.MRTD)
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q does not report a duplicate", err)
	}
}

func TestLoadImageManifestRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadImageManifest(path); err == nil {
		t.Fatal("loaded a JSON array as an image manifest")
	}
}
