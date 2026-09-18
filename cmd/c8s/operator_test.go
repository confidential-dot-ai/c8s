//go:build !c8s_node

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

func TestOperatorMeasurementsPolicyPreservesCompleteIdentities(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "testdata", "node-identities.json")
	want, err := refvalues.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := operatorMeasurementsPolicy(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := refvalues.Parse([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || !got.HasAnchors() {
		t.Fatalf("operator lost image/operator-key identities: %+v", got)
	}
	for _, flat := range []struct{ digests, rtmrs []string }{
		{digests: []string{strings.Repeat("ab", 48)}},
		{rtmrs: []string{"1=" + strings.Repeat("cd", 48)}},
	} {
		if _, err := operatorMeasurementsPolicy(path, flat.digests, flat.rtmrs); err == nil {
			t.Fatal("accepted policy with conflicting flat pins")
		}
	}
	if got, err := operatorMeasurementsPolicy("", []string{strings.Repeat("ab", 48)}, nil); err != nil || got != "" {
		t.Fatalf("legacy flags require no JSON policy: %q, %v", got, err)
	}
}

func TestOperatorMeasurementsPolicyFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if _, err := operatorMeasurementsPolicy(path, nil, nil); err == nil {
		t.Fatal("accepted missing policy")
	}
	if err := os.WriteFile(path, []byte(`{"not_a_policy":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := operatorMeasurementsPolicy(path, nil, nil); err == nil {
		t.Fatal("accepted malformed policy")
	}
}
