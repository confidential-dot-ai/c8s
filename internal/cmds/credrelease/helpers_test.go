package credrelease

import (
	"encoding/pem"
	"testing"
)

// defaultRoles is the binary-default identity set (what the baked unit spells
// out), for handler tests.
func defaultRoles() Roles {
	return Config{
		CertOrg: defaultCertOrg, CertCN: defaultCertCN, CertTTL: defaultCertTTL,
		LogCertOrg: defaultLogCertOrg, LogCertCN: defaultLogCertCN, LogCertTTL: defaultLogCertTTL,
	}.roles()
}

// decodeOnePEM decodes a single PEM block and asserts its type.
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
