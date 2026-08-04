package allowlist

import "testing"

// A requested path is rejected unless it is already canonical: the request path
// and the store key must be the same bytes, so nothing here may repair input.
func TestCanonicalSecretPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"simple", "/db/password", true},
		{"single segment", "/token", true},
		{"root", "/", true},
		{"empty", "", false},
		{"relative", "db/password", false},
		{"trailing slash", "/db/", false},
		{"double slash", "//db", false},
		{"dotdot", "/db/../etc", false},
		{"dot", "/db/./x", false},
		{"percent encoded slash", "/db%2Fpassword", false},
		{"percent encoded dot", "/db/%2e%2e/x", false},
		{"wildcard", "/db/*", false},
		{"subtree glob", "/db/**", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalSecretPath(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("CanonicalSecretPath(%q) = %v, want ok", tc.in, err)
				}
				if got != tc.in {
					t.Fatalf("CanonicalSecretPath(%q) = %q, want it unchanged", tc.in, got)
				}
				return
			}
			if err == nil {
				t.Fatalf("CanonicalSecretPath(%q) = %q, want an error", tc.in, got)
			}
		})
	}
}

func TestSecretsPolicyAllows(t *testing.T) {
	grant := &SecretsPolicy{
		Policy: PolicyAllow,
		Read:   []string{"/tenant/a/**", "/shared/token"},
		Write:  []string{"/tenant/a/**"},
	}
	for _, tc := range []struct {
		name  string
		path  string
		op    Op
		allow bool
	}{
		{"exact read", "/shared/token", OpRead, true},
		{"subtree read", "/tenant/a/db", OpRead, true},
		{"nested subtree read", "/tenant/a/deep/nested/key", OpRead, true},
		{"subtree base itself", "/tenant/a", OpRead, false},
		{"sibling prefix", "/tenant/ab", OpRead, false},
		{"other tenant", "/tenant/b/db", OpRead, false},
		{"exact grant is not a subtree", "/shared/token/more", OpRead, false},
		{"write inside subtree", "/tenant/a/db", OpWrite, true},
		{"read-only path is not writable", "/shared/token", OpWrite, false},
		{"unrelated", "/other", OpRead, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := grant.Allows(tc.path, tc.op); got != tc.allow {
				t.Fatalf("Allows(%q, %v) = %v, want %v", tc.path, tc.op, got, tc.allow)
			}
		})
	}
}

// A deny grant (the default for an entry that says nothing) allows nothing,
// including paths that appear in its own lists.
func TestSecretsPolicyDenyAllowsNothing(t *testing.T) {
	deny := &SecretsPolicy{Policy: PolicyDeny, Read: []string{"/a"}}
	if deny.Allows("/a", OpRead) {
		t.Fatal("deny policy released a path")
	}
	if (&SecretsPolicy{}).Allows("/a", OpRead) {
		t.Fatal("zero policy released a path")
	}
	var absent *SecretsPolicy
	if absent.Allows("/a", OpRead) {
		t.Fatal("absent policy released a path")
	}
}

// The root subtree covers everything below it but not "/" itself, so a grant
// cannot be widened by asking for the root.
func TestSecretsPolicyRootSubtree(t *testing.T) {
	root := &SecretsPolicy{Policy: PolicyAllow, Read: []string{"/**"}}
	if !root.Allows("/anything/at/all", OpRead) {
		t.Fatal("root subtree did not cover a nested path")
	}
	if root.Allows("/", OpRead) {
		t.Fatal("root subtree covered / itself")
	}
}

// normalizeSecrets is the write-time gate: "any" is not a secrets policy, and a
// write grant with no read is unusable by the only client there is.
func TestNormalizeSecretsRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   SecretsPolicy
	}{
		{"any", SecretsPolicy{Policy: PolicyAny}},
		{"unknown", SecretsPolicy{Policy: "sometimes"}},
		{"write without read", SecretsPolicy{Policy: PolicyAllow, Write: []string{"/w"}}},
		{"allow with nothing", SecretsPolicy{Policy: PolicyAllow}},
		{"deny with paths", SecretsPolicy{Policy: PolicyDeny, Read: []string{"/a"}}},
		{"relative glob", SecretsPolicy{Policy: PolicyAllow, Read: []string{"a/b"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &tc.in
			if err := normalizeSecrets(&p); err == nil {
				t.Fatalf("normalizeSecrets(%+v) = nil, want an error", tc.in)
			}
		})
	}
}

// An explicit deny, and an absent grant, both canonicalize to no grant at all,
// so an entry that releases nothing serializes exactly as it did before the
// field existed.
func TestNormalizeSecretsDropsEmptyGrant(t *testing.T) {
	p := &SecretsPolicy{Policy: PolicyDeny}
	if err := normalizeSecrets(&p); err != nil {
		t.Fatalf("normalizeSecrets: %v", err)
	}
	if p != nil {
		t.Fatalf("deny grant = %+v, want it dropped to nil", p)
	}
	var absent *SecretsPolicy
	if err := normalizeSecrets(&absent); err != nil || absent != nil {
		t.Fatalf("absent grant: %v %+v", err, absent)
	}
}
