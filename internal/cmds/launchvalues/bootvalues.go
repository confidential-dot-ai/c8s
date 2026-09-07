package launchvalues

import (
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// bootDerivedValues builds the values tree only a running, attested boot can
// supply: this guest's own launch measurement (pinning cds and ratlsMesh to
// exactly the image that is running, the way `c8s install --measurements`
// does on a live cluster), the matching TDX RTMR pins, and — on an operator
// boot — the operator key LoadMeasuredOperatorKey already verified against
// the launch binding. operatorPubPEM is nil on a non-operator boot (no
// opkeydata pubkey): cds.operatorKeys is then left at the chart's own ""
// default, same as omitting it. A fragment is merged UNDER this tree (see
// Render, helmchart.MergeValues), so none of these keys can be overridden by
// anything opkeydata carries.
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
	if pins := ratls.FormatRTMRPins(rtmrs); len(pins) > 0 {
		anyPins := make([]any, len(pins))
		for i, p := range pins {
			anyPins[i] = p
		}
		cds["rtmrs"] = anyPins
		ratlsMesh["rtmrs"] = anyPins
	}
	return map[string]any{
		"cds":       cds,
		"ratlsMesh": ratlsMesh,
	}
}
