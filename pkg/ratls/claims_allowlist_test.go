package ratls

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func v3Claims(allowlist byte) *ConfigClaims {
	return &ConfigClaims{
		OperatorKeysDigest: UnsetDigest(),
		SeedDigest:         UnsetDigest(),
		WorkloadDigest:     UnsetDigest(),
		MeshCADigest:       UnsetDigest(),
		AllowlistDigest:    bytes.Repeat([]byte{allowlist}, ClaimsDigestSize),
	}
}

// The live-allowlist digest must survive a marshal/unmarshal round trip, and
// the emitted encoding must be v3.
func TestAllowlistDigestRoundTrips(t *testing.T) {
	ext, err := v3Claims(0x7A).MarshalExtension()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var probe struct {
		Version int
		Rest    asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ext.Value, &probe); err != nil {
		t.Fatalf("probe version: %v", err)
	}
	if probe.Version != 3 {
		t.Fatalf("emitted config-claims version = %d, want 3", probe.Version)
	}

	got, err := UnmarshalConfigClaims(ext.Value)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(got.AllowlistDigest, bytes.Repeat([]byte{0x7A}, ClaimsDigestSize)) {
		t.Fatalf("AllowlistDigest = %x", got.AllowlistDigest)
	}
	if !got.HasAllowlist() {
		t.Fatal("HasAllowlist() = false on claims carrying a real digest")
	}
}

// A v2 certificate predates the field. It must still parse — an in-place CDS
// upgrade must not invalidate already-issued leaves — but the absent field
// must read as the sentinel so it can never satisfy a real pin. This is the
// downgrade case: old claims must not be accepted as evidence of a new
// property.
func TestV2ClaimsCannotSatisfyAnAllowlistPin(t *testing.T) {
	v2, err := asn1.Marshal(configClaimsASN1V2{
		Version:            2,
		OperatorKeysDigest: UnsetDigest(),
		SeedDigest:         UnsetDigest(),
		WorkloadDigest:     UnsetDigest(),
		MeshCADigest:       UnsetDigest(),
	})
	if err != nil {
		t.Fatalf("marshal v2: %v", err)
	}

	claims, err := UnmarshalConfigClaims(v2)
	if err != nil {
		t.Fatalf("v2 claims must still parse: %v", err)
	}
	if claims.HasAllowlist() {
		t.Fatal("v2 claims report an allowlist digest they cannot carry")
	}
	if !bytes.Equal(claims.AllowlistDigest, unsetDigest) {
		t.Fatalf("absent AllowlistDigest = %x, want the sentinel", claims.AllowlistDigest)
	}

	// The pin must reject, not silently pass.
	err = checkClaimsPins(v2, &VerifyPolicy{
		AllowlistDigest: bytes.Repeat([]byte{0x11}, ClaimsDigestSize),
	})
	if err == nil {
		t.Fatal("a v2 certificate satisfied a live-allowlist pin it never carried")
	}
}

// A pin the enforcement path cannot check must fail closed rather than be
// dropped. VerifyAttestation never sees the certificate, so claims pins are
// unenforceable there — the regression this guards is a new pin being added to
// the policy struct but omitted from that guard, which reads as enforced and
// enforces nothing.
func TestAllowlistPinRejectedByVerifyAttestation(t *testing.T) {
	_, err := VerifyAttestation(nil, &Attestation{}, &VerifyPolicy{
		AttestationApiURL: "http://127.0.0.1:1",
		AllowlistDigest:   bytes.Repeat([]byte{0x11}, ClaimsDigestSize),
	}, nil)
	if err == nil {
		t.Fatal("VerifyAttestation accepted a config-claims pin it cannot enforce")
	}
}

// Both directions on the pin itself.
func TestAllowlistPinMatchAndMismatch(t *testing.T) {
	ext, err := v3Claims(0xAA).MarshalExtension()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := checkClaimsPins(ext.Value, &VerifyPolicy{
		AllowlistDigest: bytes.Repeat([]byte{0xAA}, ClaimsDigestSize),
	}); err != nil {
		t.Fatalf("matching allowlist pin rejected: %v", err)
	}

	if err := checkClaimsPins(ext.Value, &VerifyPolicy{
		AllowlistDigest: bytes.Repeat([]byte{0xBB}, ClaimsDigestSize),
	}); err == nil {
		t.Fatal("mismatched allowlist pin accepted")
	}
}

// A wrong-size digest must be refused at marshal time, like every other claims
// field.
func TestAllowlistDigestWrongSizeRejected(t *testing.T) {
	c := v3Claims(0x01)
	c.AllowlistDigest = []byte{1, 2}
	if _, err := c.MarshalExtension(); err == nil {
		t.Fatal("marshal accepted a wrong-size allowlist digest")
	}
}
