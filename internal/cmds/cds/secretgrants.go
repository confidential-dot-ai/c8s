package cds

import (
	"fmt"
	"path"
	"slices"
	"strings"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// resolveEntries returns the names of workload entries whose non-floor
// init/main digest sets exactly equal the claimed sets, sorted for
// determinism. It mirrors enforceWorkloadCombination (attest.go) but returns
// the matches: the fetch gate needs the granting entry, and more than one
// match is an ambiguity the caller must fail closed on (docs/secrets-broker.md).
func resolveEntries(doc *pkgallowlist.Allowlist, initDigests, mainDigests []string) []string {
	floor := doc.Digests
	claimInit := nonFloorSet(initDigests, floor)
	claimMain := nonFloorSet(mainDigests, floor)
	if len(claimInit) == 0 && len(claimMain) == 0 {
		return nil
	}
	var matches []string
	for name, w := range doc.Workloads {
		if setsEqual(claimInit, nonFloorSet(digestStrings(w.InitContainers), floor)) &&
			setsEqual(claimMain, nonFloorSet(digestStrings(w.Containers), floor)) {
			matches = append(matches, name)
		}
	}
	slices.Sort(matches)
	return matches
}

// grantFor reports whether the entry grants op access to path for digest.
// Grants are the union across the entry's containers with that digest (the
// per-container semantic of AdmitsContainer). deny grants nothing; any grants
// any requested path; allow glob-matches (trailing /** is a subtree).
func grantFor(entry *pkgallowlist.Workload, digest types.Digest, p string, write bool) bool {
	for _, c := range slices.Concat(entry.InitContainers, entry.Containers) {
		if c.Digest != digest {
			continue
		}
		switch c.Paths.Policy {
		case pkgallowlist.PolicyAny:
			return true
		case pkgallowlist.PolicyAllow:
			globs := c.Paths.Read
			if write {
				globs = c.Paths.Write
			}
			for _, g := range globs {
				if pathMatches(g, p) {
					return true
				}
			}
		}
	}
	return false
}

// entryHasDigest reports whether the digest appears anywhere in the entry.
func entryHasDigest(entry *pkgallowlist.Workload, digest types.Digest) bool {
	for _, c := range slices.Concat(entry.InitContainers, entry.Containers) {
		if c.Digest == digest {
			return true
		}
	}
	return false
}

// validRequestPath enforces the request-side path form: absolute and clean,
// no wildcards (grants carry the globs, requests name concrete files).
func validRequestPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if strings.Contains(p, "*") {
		return fmt.Errorf("path %q: wildcards belong in policy, not requests", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("path %q is not clean (no . or ..)", p)
	}
	return nil
}

// pathMatches matches a policy glob against a request path: a trailing "/**"
// is a subtree match, anything else is exact.
func pathMatches(glob, p string) bool {
	if base, ok := strings.CutSuffix(glob, "/**"); ok {
		if base == "" {
			return strings.HasPrefix(p, "/")
		}
		return p == base || strings.HasPrefix(p, base+"/")
	}
	return glob == p
}
