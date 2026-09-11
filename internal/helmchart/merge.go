package helmchart

// MergeValues deep-merges src onto dst the way helm coalesces a -f values
// file: a map value recurses, anything else (scalar, list) replaces. dst is
// mutated in place and returned.
//
// No build tag: unlike ChartFS (embed.go, excluded from -tags c8s_node),
// this is pure value-tree logic with no chart dependency, so both cmd/c8s's
// install/render-values path and internal/cmds/launchvalues (which DOES
// build under c8s_node, for the node image's own boot-time render) can share
// it.
func MergeValues(dst, src map[string]any) map[string]any {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				MergeValues(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
	return dst
}
