package verify

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func discoveryDocWith(t *testing.T, certPEM string, challenge []byte, evidence string) []byte {
	t.Helper()
	doc := map[string]any{
		"cds_tls": map[string]any{"certificate_pem": certPEM},
		"attestation": map[string]any{
			"challenge": base64.StdEncoding.EncodeToString(challenge),
			"platform":  "snp",
			"evidence":  json.RawMessage(evidence),
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery doc: %v", err)
	}
	return data
}
