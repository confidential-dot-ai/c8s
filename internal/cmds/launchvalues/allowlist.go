package launchvalues

import (
	"fmt"
	"strings"
)

// allowedPrefixes is the explicit launch-time values allowlist (Phase 0b of
// the credential-release design): deployment configuration that
// `c8s install --values` used to carry and that must not need an image
// rebuild, but that must also not be trusted from the host-attached
// opkeydata disk unauthenticated beyond this set. Every entry is a path or a
// path prefix ending in "." (covering a whole subtree, e.g. every CORS
// knob). Checked against every internal/helmchart/c8s/values.yaml).
//
// Anything not covered here is denied by construction, in particular every
// image/digest/tag, attestationApi.*, hostNamespacePolicy, cds.image,
// cds.ratlsPlatform, ratlsMesh.image, ratlsMesh.enabled, ratlsMesh.platform,
// webhook.enabled, kata.*, operator.*, and nriImagePolicy.{enabled,baked,
// image,distro} — none of them are on the list below, so the leaf walk in
// checkAllowlist rejects them the same way it rejects a typo.
var allowedPrefixes = []string{
	"tlsLb.san",
	"tlsLb.cors.",
	"cds.dnsSanPatterns",
	"cds.measurementsConfig",
	"cds.rateLimit",
	"cds.rateBurst",
	"ratlsMesh.measurementsConfig",
	"volumed.enabled",
	"nriImagePolicy.policy.exemptNamespaces",
	"nriImagePolicy.bootstrapAllowlist.digests.",
}

// checkAllowlist walks every leaf of values and fails closed on the first
// path that is not exactly one of allowedPrefixes or under one ending in
// ".". cds.operatorKeys and the measurement/rtmr keys are never reachable
// through the fragment at all — they are not on the list, so a fragment that
// tries to set them is rejected here, before the merge that would otherwise
// let a map-shaped attempt shadow them.
func checkAllowlist(values map[string]any) error {
	return walkLeaves(values, "", func(path string) error {
		if !allowedPath(path) {
			return fmt.Errorf("launch-values fragment: %q is not on the launch-time values allowlist (see internal/cmds/launchvalues.allowedPrefixes)", path)
		}
		return nil
	})
}

// allowedPath reports whether path is covered by allowedPrefixes: an exact
// match, or under a prefix entry ending in "." (e.g. "tlsLb.cors." covers
// "tlsLb.cors.enabled").
func allowedPath(path string) bool {
	for _, p := range allowedPrefixes {
		if strings.HasSuffix(p, ".") {
			if strings.HasPrefix(path, p) {
				return true
			}
			continue
		}
		if path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}

// walkLeaves calls fn with the dotted path of every leaf in tree (a scalar,
// a list, or an empty map — anything that is not itself a non-empty map).
// An empty map is treated as a leaf so a fragment that sets, say,
// `tlsLb.cors: {}` is still checked against the allowlist rather than
// silently vanishing from the walk.
func walkLeaves(tree map[string]any, prefix string, fn func(path string) error) error {
	if len(tree) == 0 {
		if prefix == "" {
			return nil
		}
		return fn(prefix)
	}
	for k, v := range tree {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if m, ok := v.(map[string]any); ok {
			if err := walkLeaves(m, path, fn); err != nil {
				return err
			}
			continue
		}
		if err := fn(path); err != nil {
			return err
		}
	}
	return nil
}
