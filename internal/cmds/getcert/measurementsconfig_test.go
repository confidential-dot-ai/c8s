package getcert

import (
	"bytes"
	"os"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

func TestCDSPinsPreserveOperatorIdentities(t *testing.T) {
	const path = "../../../pkg/measurements/testdata/node-identities.json"
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := measurements.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []config{{MeasurementsConfig: path}, {MeasurementsConfigJSON: string(doc)}} {
		pins, err := cdsPins(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(pins.Entries) != len(want.Entries) || !bytes.Equal(pins.Entries[0].OperatorKey, want.Entries[0].OperatorKey) {
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
