package credrelease

import (
	"encoding/pem"
	"testing"
)

// decodeOnePEM decodes a single PEM block and asserts its type.
// defaultRoles is the binary-default identity set (what the baked unit spells
// out), for handler tests.
func defaultRoles() Roles {
	return Roles{
		Operator:  Identity{Org: defaultCertOrg, CN: defaultCertCN, TTL: defaultCertTTL},
		LogReader: Identity{Org: defaultLogCertOrg, CN: defaultLogCertCN, TTL: defaultLogCertTTL},
	}
}

func decodeOnePEM(t *testing.T, pemBytes []byte, wantType string) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("no PEM block")
	}
	if block.Type != wantType {
		t.Fatalf("PEM type = %q, want %q", block.Type, wantType)
	}
	return block.Bytes
}
