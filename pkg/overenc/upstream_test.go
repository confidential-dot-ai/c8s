package overenc

import (
	"strings"
	"testing"
)

// The same destination, spelled every way the canonicaliser normalises, must
// produce exactly one commitment.
func TestCanonicalUpstreamURLEquivalence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		equivalent []string
		want       string
	}{
		{
			name: "scheme and host case, default port, root dot, bare slash",
			equivalent: []string{
				"http://c8s-infer.c8s-system.svc.cluster.local:8000",
				"HTTP://c8s-infer.c8s-system.svc.cluster.local:8000",
				"http://C8S-Infer.C8S-System.SVC.Cluster.Local:8000",
				"http://c8s-infer.c8s-system.svc.cluster.local.:8000",
				"http://c8s-infer.c8s-system.svc.cluster.local:8000/",
				"http://c8s-infer.c8s-system.svc.cluster.local:8000//",
				"http://c8s-infer.c8s-system.svc.cluster.local:08000",
				" http://c8s-infer.c8s-system.svc.cluster.local:8000 ",
			},
			want: "http://c8s-infer.c8s-system.svc.cluster.local:8000",
		},
		{
			name: "http default port elided",
			equivalent: []string{
				"http://backend:80", "http://backend", "http://backend:80/",
				"http://backend:080", "HTTP://BACKEND:80",
			},
			want: "http://backend",
		},
		{
			name: "https default port elided",
			equivalent: []string{
				"https://backend:443", "https://backend", "https://backend:443/",
				"HTTPS://Backend.:0443",
			},
			want: "https://backend",
		},
		{
			name: "dot-segments resolve to one prefix",
			equivalent: []string{
				"http://backend/api", "http://backend/api/", "http://backend/./api",
				"http://backend/x/../api", "http://backend/api/.", "http://backend/x/y/../../api",
				"http://backend/%2e/api", "http://backend/%2E%2e/api",
			},
			want: "http://backend/api",
		},
		{
			name: "dot-segments cannot climb above the root",
			equivalent: []string{
				"http://backend", "http://backend/", "http://backend/.", "http://backend/..",
				"http://backend/a/..", "http://backend/a/b/../..", "http://backend/../..",
			},
			want: "http://backend",
		},
		{
			name: "unreserved percent-encodings decode",
			equivalent: []string{
				"http://backend/a~b", "http://backend/a%7eb", "http://backend/a%7Eb",
			},
			want: "http://backend/a~b",
		},
		{
			name:       "IPv6 literal",
			equivalent: []string{"http://[::1]:8080/", "http://[::1]:8080"},
			want:       "http://[::1]:8080",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, raw := range tc.equivalent {
				got, err := CanonicalUpstreamURL(raw)
				if err != nil {
					t.Fatalf("CanonicalUpstreamURL(%q): %v", raw, err)
				}
				if got != tc.want {
					t.Fatalf("CanonicalUpstreamURL(%q) = %q, want %q", raw, got, tc.want)
				}
			}
		})
	}
}

// Different destinations must keep different commitments: host, port, scheme,
// and reserved path bytes all discriminate.
func TestCanonicalUpstreamURLDiscrimination(t *testing.T) {
	for _, tc := range []struct {
		a, b string
	}{
		{"http://backend:8000", "http://backend:8001"},
		{"http://backend", "http://backend:8000"},
		{"http://backend", "https://backend"},
		{"http://backend", "http://backend2"},
		{"http://backend", "http://backend.evil.com"},
		{"http://backend/api", "http://backend/api2"},
		// A reserved encoding is not its decoded byte: %2F is not a separator.
		{"http://backend/a%2Fb", "http://backend/a/b"},
		// A non-default port survives; the other scheme's default is not elided.
		{"http://backend:443", "http://backend"},
		{"https://backend:80", "https://backend"},
	} {
		ca, err := CanonicalUpstreamURL(tc.a)
		if err != nil {
			t.Fatalf("CanonicalUpstreamURL(%q): %v", tc.a, err)
		}
		cb, err := CanonicalUpstreamURL(tc.b)
		if err != nil {
			t.Fatalf("CanonicalUpstreamURL(%q): %v", tc.b, err)
		}
		if ca == cb {
			t.Fatalf("CanonicalUpstreamURL(%q) == CanonicalUpstreamURL(%q) = %q, want distinct commitments", tc.a, tc.b, ca)
		}
	}
}

// Userinfo, query, and fragment are rejected rather than committed verbatim;
// non-http(s) schemes and host-less URLs are not destinations.
func TestCanonicalUpstreamURLRejects(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		wantSub string
	}{
		{"http://user@backend/", "userinfo"},
		{"http://user:pw@backend:8000", "userinfo"},
		{"http://backend/?x=1", "query"},
		{"http://backend?", "query"},
		{"http://backend/#frag", "fragment"},
		{"http://backend#", "fragment"},
		{"http://backend:0/", "real port"},
		{"http://backend:65536/", "real port"},
		{"http://backend:99999999999999999999/", "real port"},
		{"ftp://backend", "http:// or https://"},
		{"backend:8000", "http:// or https://"},
		{"http://", "no host"},
		{"http://:8080/", "no host"},
		{"http:backend", "no host"},
		{"", "http:// or https://"},
		{"http://backend:abc/", "does not parse"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			_, err := CanonicalUpstreamURL(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("CanonicalUpstreamURL(%q) error = %v, want substring %q", tc.raw, err, tc.wantSub)
			}
		})
	}
}

func TestCanonicalDNSName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Backend.Other.SVC", "backend.other.svc"},
		{"backend.other.svc.", "backend.other.svc"},
		{"backend.other.svc", "backend.other.svc"},
		{"10.96.0.15", "10.96.0.15"},
		{"", ""},
	} {
		if got := CanonicalDNSName(tc.in); got != tc.want {
			t.Fatalf("CanonicalDNSName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
