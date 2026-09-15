package getcert

import (
	"bytes"
	"os"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

func TestCDSPinsPreserveOperatorIdentities(t *testing.T) {
	const path = "../../../internal/testdata/node-identities.json"
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := refvalues.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []config{{MeasurementsConfig: path}, {MeasurementsConfigJSON: string(doc)}} {
		pins, err := cdsPins(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(pins.Images) != len(want.Images) || !bytes.Equal(pins.Images[0].Anchor, want.Images[0].Anchor) {
			t.Fatal("CDS client dropped the operator identity")
		}
		if len(pins.Measurements) != 0 || len(pins.RTMRs) != 0 {
			t.Fatal("complete policy produced a second flat fallback")
		}
	}
	for _, cfg := range []config{
		{MeasurementsConfig: path, MeasurementsConfigJSON: string(doc)},
		{MeasurementsConfig: path, CDSMeasurements: "ab"},
		{MeasurementsConfigJSON: string(doc), CDSRTMRs: "1=ab"},
		{MeasurementsConfig: "missing-file"},
		{MeasurementsConfigJSON: `{}`},
	} {
		if _, err := cdsPins(cfg); err == nil {
			t.Fatal("invalid or mixed source accepted")
		}
	}
}
