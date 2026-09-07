package launchvalues

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
)

// bootDerivedValues builds the values tree only a running, attested boot can
// supply: this guest's own launch measurement (pinning cds and ratlsMesh to
// exactly the image that is running, the way `c8s install --measurements`
// does on a live cluster), the matching TDX RTMR pins, and — on an operator
// boot — the operator key LoadMeasuredOperatorKey already verified against
// the launch binding. operatorPubPEM is nil on a non-operator boot (no
// opkeydata pubkey): cds.operatorKeys is then left at the chart's own ""
// default, same as omitting it. A fragment is deep-merged UNDER this tree
// (see Render), so none of these keys can be overridden by anything
// opkeydata carries.
func bootDerivedValues(operatorPubPEM []byte, ownMeasurementHex string, rtmrs map[int][]byte) map[string]any {
	cds := map[string]any{
		"measurements": []any{ownMeasurementHex},
	}
	if operatorPubPEM != nil {
		cds["operatorKeys"] = string(operatorPubPEM)
	}
	ratlsMesh := map[string]any{
		"measurements": []any{ownMeasurementHex},
	}
	if pins := rtmrPinStrings(rtmrs); len(pins) > 0 {
		cds["rtmrs"] = pins
		ratlsMesh["rtmrs"] = pins
	}
	return map[string]any{
		"cds":       cds,
		"ratlsMesh": ratlsMesh,
	}
}

// rtmrPinStrings formats rtmrs as "<index>=<hex>" strings in index order —
// the same shape cds.rtmrs/ratlsMesh.rtmrs take in cmd/c8s/install.go and
// c8s-chart-values.sh's RTMR_PINS.
func rtmrPinStrings(rtmrs map[int][]byte) []any {
	if len(rtmrs) == 0 {
		return nil
	}
	out := make([]any, 0, len(rtmrs))
	for _, idx := range slices.Sorted(maps.Keys(rtmrs)) {
		out = append(out, fmt.Sprintf("%d=%s", idx, hex.EncodeToString(rtmrs[idx])))
	}
	return out
}

// deepMerge merges src onto dst: a map value recurses, anything else
// (scalar, list) replaces — the same coalescing shape helm applies for a -f
// values file (see mergeValues in cmd/c8s/install.go). dst is mutated in
// place. Called with dst = the boot-derived tree and src = the fragment's
// values, so a fragment can shadow a boot-derived scalar leaf but can never
// remove or type-change a boot-derived key it does not carry, and (thanks to
// the allowlist walk in checkAllowlist) never touches cds.operatorKeys,
// cds.measurements/rtmrs, or ratlsMesh.measurements/rtmrs at all.
func deepMerge(dst, src map[string]any) {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}
