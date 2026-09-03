package allowlist

import "testing"

func TestBindSource(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/etc/cni/net.d/", "/etc/cni/net.d"},
		{"/var/run/nri-image-policy", "/run/nri-image-policy"},
		{"/var/run/nri-image-policy/", "/run/nri-image-policy"},
		{"/var/run", "/run"},
		{"/var/runtime", "/var/runtime"},
		{"/var/runner/x", "/var/runner/x"},
		{"/dev/../etc", "/etc"},
		{"/lib/modules/../modules", "/lib/modules"},
	} {
		if got := BindSource(tc.in); got != tc.want {
			t.Errorf("BindSource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnderDir(t *testing.T) {
	for _, tc := range []struct {
		p, dir string
		want   bool
	}{
		{"/run/confai", "/run/confai", true},
		{"/run/confai/policy", "/run/confai", true},
		{"/run/confai-evil/x", "/run/confai", false},
		{"/run", "/run/confai", false},
		{"/anything", "", false},
	} {
		if got := UnderDir(tc.p, tc.dir); got != tc.want {
			t.Errorf("UnderDir(%q, %q) = %v, want %v", tc.p, tc.dir, got, tc.want)
		}
	}
}
