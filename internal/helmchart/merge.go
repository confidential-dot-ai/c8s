package helmchart

// MergeValues deep-merges src onto dst the way helm coalesces a -f values
// file: a map value recurses, anything else (scalar, list) replaces. dst is
// mutated in place and returned.
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
