package cdsconn

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

const nodePolicyPath = "../../../pkg/measurements/testdata/node-identities.json"

func TestOperatorCLIConfigRejectsDowngrades(t *testing.T) {
	o := Options{URL: "https://cds.example", MeasurementsConfig: nodePolicyPath, OperatorKey: writeTestKey(t)}
	pins, err := o.loadPins()
	if err != nil || len(pins.Entries) != 2 || len(pins.Entries[0].OperatorKey) == 0 {
		t.Fatalf("full policy lost: %v", err)
	}
	if _, err := o.Signer(); err != nil {
		t.Fatalf("full policy did not satisfy write pinning requirement: %v", err)
	}
	for _, cfg := range []Options{
		{MeasurementsConfig: nodePolicyPath, Measurements: []string{"ab"}},
		{MeasurementsConfig: nodePolicyPath, MeasurementsFile: "legacy.txt"},
		{MeasurementsConfig: "missing-file"},
	} {
		if _, err := cfg.loadPins(); err == nil {
			t.Fatal("invalid or mixed config fell back to flat policy")
		}
	}
	o.URL, o.Insecure = "http://cds.example", true
	if _, err := o.HTTPClient(context.Background()); err == nil {
		t.Fatal("plaintext silently ignored the operator identity policy")
	}
}

func TestOperatorCLIVerifierRejectsAgentAndCrossedTuple(t *testing.T) {
	all, err := measurements.Load(nodePolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	pins := measurements.ReferenceValues{TEE: all.TEE, Entries: all.Entries[:1]}
	server := pins.Entries[0]
	var report *teetypes.VerificationResult
	o := Options{MeasurementsConfig: nodePolicyPath, Verify: func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		return report, nil
	}}
	verify := o.pinnedVerifier(pins)
	for _, test := range []struct {
		name     string
		key      []byte
		register []byte
		accept   bool
	}{
		{"server", server.OperatorKey, server.RTMRs[1], true},
		{"agent same image", all.Entries[1].OperatorKey, server.RTMRs[1], false},
		{"server wrong image registers", server.OperatorKey, server.RTMRs[2], false},
	} {
		t.Run(test.name, func(t *testing.T) {
			seed := runtimemeasure.Seed(test.key)
			report = &teetypes.VerificationResult{Platform: teetypes.PlatformTDX, SignatureValid: true}
			report.Claims.LaunchDigest = hex.EncodeToString(server.Digest)
			report.Claims.PlatformData = map[string]any{
				"rtmr_1": hex.EncodeToString(test.register),
				"rtmr_2": hex.EncodeToString(server.RTMRs[2]),
				"rtmr_3": hex.EncodeToString(seed[:]),
			}
			_, err := verify(context.Background(), "tdx", nil, localverify.Params{})
			if (err == nil) != test.accept {
				t.Fatalf("accept=%v, error=%v", test.accept, err)
			}
		})
	}
	report = nil
	if _, err := verify(context.Background(), "tdx", nil, localverify.Params{}); err == nil {
		t.Fatal("nil verified claims accepted")
	}
}
