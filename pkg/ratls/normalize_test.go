package ratls

import "testing"

func TestNormalizePlatform(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", ""},
		{" ", ""},
		{"snp", "sev-snp"},
		{"SEV-SNP", "sev-snp"},
		{"tdx", "tdx"},
		{"unknown", "unknown"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizePlatform(tc.input); got != tc.want {
				t.Fatalf("NormalizePlatform(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestRejectCloudPlatformAliases(t *testing.T) {
	for _, platform := range []string{"az-snp", "az-tdx", "gcp-snp", "gcp-tdx"} {
		if err := ValidatePlatform(platform); err == nil {
			t.Errorf("accepted removed platform %q", platform)
		}
	}
}
