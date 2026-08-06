package nriimagepolicy

import "testing"

func TestExtractDigest(t *testing.T) {
	const hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	tests := []struct {
		input, want string
	}{
		{"registry/repo@sha256:" + hex, "sha256:" + hex},
		{"registry/repo:tag@sha256:" + hex, "sha256:" + hex},
		// A malformed digest is "no digest": the caller must resolve or deny,
		// never carry garbage into an allowlist comparison.
		{"registry/repo@sha256:abc123", ""},
		{"registry/repo:latest", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractDigest(tt.input)
		if got != tt.want {
			t.Errorf("extractDigest(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
