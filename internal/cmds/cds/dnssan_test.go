package cds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSFileAddsOnlyTheLiteralHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls-san")
	if err := os.WriteFile(path, []byte("c8s.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	patterns, err := compileDNSPatterns([]string{`^[a-z0-9-]+[.][a-z0-9-]+[.]svc$`}, path)
	if err != nil || len(patterns) != 2 {
		t.Fatalf("patterns: %v, %v", patterns, err)
	}
	if !patterns[0].MatchString("mesh.c8s.svc") || !patterns[1].MatchString("c8s.example.com") {
		t.Fatal("lost service DNS or authenticated SAN")
	}
	for _, name := range []string{"c8sXexampleXcom", "evil.c8s.example.com", "c8s.example.com.evil"} {
		if patterns[1].MatchString(name) {
			t.Errorf("accepted %q", name)
		}
	}
}

func TestDNSFileRejectsMissingOrNonDNSIdentity(t *testing.T) {
	for _, value := range []string{"", "\n", "192.0.2.1", "2001:db8::1", ".*", "*.example.com", "^example[.]com$", "https://example.com", "one.example\ntwo.example", strings.Repeat("x", 1025)} {
		path := filepath.Join(t.TempDir(), "tls-san")
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := compileDNSPatterns([]string{`.*`}, path); err == nil {
			t.Errorf("accepted invalid staged SAN %q despite configured patterns", value)
		}
	}
	if _, err := compileDNSPatterns(nil, filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing DNS file: %v", err)
	}
}
