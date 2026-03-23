package whitelist

import (
	"strings"
	"testing"
)

func TestParseJSON_Valid(t *testing.T) {
	data := `{"version":"1","digests":{"sha256:` + strings.Repeat("a", 64) + `":"img1"}}`
	wl, err := ParseJSON([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(wl.Digests) != 1 {
		t.Fatalf("got %d digests, want 1", len(wl.Digests))
	}
}

func TestParseJSON_EmptyDigests(t *testing.T) {
	_, err := ParseJSON([]byte(`{"version":"1","digests":{}}`))
	if err == nil {
		t.Fatal("expected error for empty digests")
	}
}

func TestParseJSON_InvalidDigest(t *testing.T) {
	_, err := ParseJSON([]byte(`{"version":"1","digests":{"baddigest":"img"}}`))
	if err == nil {
		t.Fatal("expected error for invalid digest format")
	}
}

func TestParseJSON_BadJSON(t *testing.T) {
	_, err := ParseJSON([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestContains(t *testing.T) {
	wl := &Whitelist{Digests: map[string]string{"sha256:abc": "img"}}
	if !wl.Contains("sha256:abc") {
		t.Error("expected Contains=true")
	}
	if wl.Contains("sha256:missing") {
		t.Error("expected Contains=false")
	}
}

func TestIsValidDigest(t *testing.T) {
	valid := "sha256:" + strings.Repeat("ab0c", 16) // 64 hex chars
	if !isValidDigest(valid) {
		t.Errorf("expected valid: %s", valid)
	}

	for _, bad := range []string{"", "sha256:short", "md5:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("g", 64)} {
		if isValidDigest(bad) {
			t.Errorf("expected invalid: %s", bad)
		}
	}
}
