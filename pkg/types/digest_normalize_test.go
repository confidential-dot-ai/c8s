package types

import (
	"strings"
	"testing"
)

func TestNormalizeDigest(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "canonical", in: "sha256:" + hex, want: "sha256:" + hex},
		{name: "uppercase prefix", in: "SHA256:" + hex, want: "sha256:" + hex},
		{name: "uppercase hex", in: "sha256:" + strings.ToUpper(hex), want: "sha256:" + hex},
		{name: "bare hex", in: hex, want: "sha256:" + hex},
		{name: "image ref with digest", in: "ghcr.io/acme/app@sha256:" + hex, want: "sha256:" + hex},
		{name: "surrounding whitespace", in: " sha256:" + hex + " ", want: "sha256:" + hex},
		{name: "empty", in: "", wantErr: true},
		{name: "tag only", in: "ghcr.io/acme/app:v1.0.0", wantErr: true},
		{name: "too short", in: "sha256:" + hex[:62], wantErr: true},
		{name: "not hex", in: "sha256:" + strings.Repeat("zz", 32), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDigest(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeDigest(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDigest(%q): %v", tc.in, err)
			}
			if got.String() != tc.want {
				t.Fatalf("NormalizeDigest(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
