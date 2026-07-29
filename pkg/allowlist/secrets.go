// Secret-store path grants: canonicalization and matching.
//
// Grant globs and requested paths go through the same canonical form, in this
// package, deliberately. They are compared for equality and prefix containment,
// so any divergence between how a grant is stored and how a request is read is
// a policy bypass rather than a mismatch — see docs/secrets.md.

package allowlist

import (
	"fmt"
	"path"
	"strings"
)

// Op is the access a request needs.
type Op int

const (
	OpRead Op = iota
	OpWrite
)

// subtreeSuffix marks a grant that covers a path and everything beneath it.
const subtreeSuffix = "/**"

// CanonicalSecretPath validates and canonicalizes a requested store path.
//
// It rejects rather than repairs: a path that is not already canonical is an
// error, never something silently rewritten into one. Percent-encoding is
// refused outright so "%2F" cannot alias with "/" — the request path and the
// store key must be the same bytes by construction.
func CanonicalSecretPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("secret path is empty")
	}
	if strings.Contains(p, "%") {
		return "", fmt.Errorf("secret path %q must not be percent-encoded", p)
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("secret path %q must be absolute", p)
	}
	if strings.Contains(p, "*") {
		return "", fmt.Errorf("secret path %q must not contain wildcards", p)
	}
	if p != "/" && strings.HasSuffix(p, "/") {
		return "", fmt.Errorf("secret path %q must not have a trailing slash", p)
	}
	if path.Clean(p) != p {
		return "", fmt.Errorf("secret path %q is not clean (no . or ..)", p)
	}
	return p, nil
}

// Allows reports whether the grant permits op on a canonical path. Call
// CanonicalSecretPath first; an uncanonicalized path is not matched.
//
// A nil grant — an entry that says nothing — allows nothing.
func (p *SecretsPolicy) Allows(canonicalPath string, op Op) bool {
	if p == nil || p.Policy != PolicyAllow {
		return false
	}
	globs := p.Read
	if op == OpWrite {
		globs = p.Write
	}
	for _, g := range globs {
		if matchGlob(g, canonicalPath) {
			return true
		}
	}
	return false
}

// matchGlob matches one normalized grant glob against a canonical path. A bare
// path matches only itself; a "/**" suffix matches the subtree strictly beneath
// its base, not the base itself, so granting "/a/**" does not hand over "/a".
func matchGlob(glob, p string) bool {
	base, subtree := strings.CutSuffix(glob, subtreeSuffix)
	if !subtree {
		return glob == p
	}
	if base == "" {
		base = "/"
	}
	if base == "/" {
		return strings.HasPrefix(p, "/") && p != "/"
	}
	return strings.HasPrefix(p, base+"/")
}
