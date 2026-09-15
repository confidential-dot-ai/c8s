package sidecar

import (
	"bytes"
	"os"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

func TestSidecarPolicyPreservesOperatorIdentities(t *testing.T) {
	const path = "../../../internal/testdata/node-identities.json"
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := refvalues.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{{MeasurementsConfig: path}, {MeasurementsConfigJSON: string(doc)}} {
		pins, err := cfg.ParsePins()
		if err != nil {
			t.Fatal(err)
		}
		if len(pins.Images) != len(want.Images) || !bytes.Equal(pins.Images[0].Anchor, want.Images[0].Anchor) {
			t.Fatal("sidecar dropped operator pins")
		}
	}
	for _, cfg := range []Config{
		{MeasurementsConfig: path, MeasurementsConfigJSON: string(doc)},
		{MeasurementsConfig: path, Measurements: []string{"ab"}},
		{MeasurementsConfigJSON: string(doc), RTMRs: []string{"1=ab"}},
		{MeasurementsConfig: "missing-file"},
		{MeasurementsConfigJSON: `{}`},
	} {
		if _, err := cfg.ParsePins(); err == nil {
			t.Fatal("invalid or mixed source accepted")
		}
	}
}
