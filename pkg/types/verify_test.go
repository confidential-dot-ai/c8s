package types

import (
	"encoding/json"
	"testing"
)

// The v2 bundle always names its committed destination identity: the three
// upstream fields serialize even when empty, so a committed-empty value reads
// as a stated choice, not an absent field.
func TestAttestationBundleUpstreamTripleAlwaysSerializes(t *testing.T) {
	data, err := json.Marshal(AttestationBundle{Upstream: "http://backend:8000"})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"upstream", "upstream_server_name", "upstream_ca_sha256"} {
		v, ok := parsed[key]
		if !ok {
			t.Errorf("serialized bundle missing %q: %s", key, data)
		} else if key != "upstream" && v != "" {
			t.Errorf("plaintext upstream: %s = %q, want serialized-empty", key, v)
		}
	}
}
