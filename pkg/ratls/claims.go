// Config-claims: digests of host-supplied configuration, carried on an RA-TLS
// certificate and bound into its attestation evidence, so verifiers can pin
// them the way they pin launch measurements. Normative spec, trust semantics,
// and audit map: docs/ratls.md.

package ratls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"reflect"
)

// OIDRATLSConfigClaims identifies the config-claims extension (see
// extension.go for the 1.3.6.1.4.1.59888 arc; .1.2 is taken by
// certutil.OIDAttestationDigest):
//
//	1.3.6.1.4.1.59888.1.3 - RA-TLS config-claims extension
var OIDRATLSConfigClaims = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 3}

// configClaimsVersion is the claims version this package EMITS. v1 and v2 are
// still parsed for certificates issued before meshCADigest and allowlistDigest
// existed.
const configClaimsVersion = 3

// claimsDomainSep tags the config-claims REPORTDATA transcript
// (ReportDataForKeyAndClaims), keeping it disjoint from a plain key+nonce
// binding (SHA-384(pubkey ‖ nonce)). The transcript is domain-separated AND
// length-framed, so the binding is unambiguous without relying on any field's
// length or the nonce's provenance (docs/ratls.md, Config-claims).
var claimsDomainSep = []byte("c8s/config-claims/v1\x00")

// ClaimsDigestSize is the size of each digest carried in ConfigClaims
// (SHA-256).
const ClaimsDigestSize = 32

// unsetDigest marks a claims field that does not apply to the certificate's
// role. All-zero is unreachable as a real SHA-256 output, so a verifier
// pinning a real value can never be satisfied by a sentinel.
var unsetDigest = make([]byte, ClaimsDigestSize)

// UnsetDigest returns the "not applicable" sentinel for a claims field, as a
// fresh copy so callers cannot corrupt the sentinel.
func UnsetDigest() []byte {
	return append([]byte(nil), unsetDigest...)
}

// ConfigClaims is configuration the attesting workload vouches for
// (docs/ratls.md). Every field is always present; a field that does
// not apply carries UnsetDigest. The evidence binds the marshaled claims, so
// they carry the same trust as the launch measurement — a statement by
// measured code about the configuration it actually loaded.
type ConfigClaims struct {
	// OperatorKeysDigest is the canonical digest of the operator public-key
	// set authorized to mutate the allowlist (operatorauth.KeySetDigest). The
	// empty key set is a defined digest, distinct from the sentinel, so "writes
	// disabled" is attestable. Set by CDS.
	OperatorKeysDigest []byte
	// SeedDigest is the canonical digest of the allowlist seed loaded at
	// startup (allowlist.CanonicalDigest), or UnsetDigest when no seed was
	// configured. Set by CDS.
	SeedDigest []byte
	// WorkloadDigest is present for wire compatibility only: leaves issued
	// before the sandbox-digests inventory replaced cert-carried workload
	// claims (#168) set it, and cross-client parsers decode it in every
	// claims version, so the field cannot be dropped without changing the
	// encoding. Nothing sets it anymore — every certificate issued since
	// carries UnsetDigest here, and it is not pinnable (workload identity is
	// established via the pod's admitted sandbox digests at issuance instead).
	WorkloadDigest []byte
	// MeshCADigest is SHA-256 of the issuing mesh CA's DER, or UnsetDigest on
	// certificates that do not issue under one. Set by CDS.
	//
	// This is what lets a client stop pinning the mesh CA out of band. CDS's
	// own RA-TLS certificate is self-signed and presented without a chain, so
	// attesting CDS proves "a measured CDS vouches for allowlist X" but says
	// nothing about which CA it signs leaves under — leaving the CA an
	// unauthenticated, manually distributed anchor that rotates on every
	// install. Committing its digest here folds the CA into the same hardware
	// evidence as the rest of the claims, so a verified CDS attestation
	// authenticates the CA, and the LB's leaf chaining to that CA becomes a
	// verified step rather than a trusted one.
	//
	// Present from claims v2. A v1 certificate parses with UnsetDigest here.
	MeshCADigest []byte
	// AllowlistDigest is the canonical digest of the allowlist CDS is serving
	// NOW (allowlist.CanonicalDigest over the live store), or UnsetDigest on
	// certificates that serve none. Set by CDS.
	//
	// SeedDigest answers "what was loaded at boot"; this answers "what is
	// admitted now". They are kept separate rather than one replacing the
	// other because the two are independently useful, and their divergence is
	// itself the audit signal that someone mutated the allowlist at runtime.
	// Pinning SeedDigest alone cannot catch an operator adding a permissive
	// entry post-boot — observed live, where the allowlist went version 2 to 7
	// while SeedDigest never moved.
	//
	// Freshness comes from re-issuance, not from a timestamp: CDS re-issues
	// this certificate whenever the live digest changes, so the certificate
	// fingerprint changing IS the cache-invalidation signal. A client caches
	// the verified certificate long-lived and re-attests exactly when the
	// allowlist moves — no staleness window to tune (docs/ratls.md).
	//
	// Present from claims v3. A v1/v2 certificate parses with UnsetDigest here.
	AllowlistDigest []byte
}

// configClaimsASN1V1 is the v1 DER encoding, still parsed so certificates
// issued before meshCADigest existed keep verifying (docs/ratls.md,
// Config-claims).
//
//	C8SConfigClaims ::= SEQUENCE {
//	    version             INTEGER,
//	    operatorKeysDigest  OCTET STRING,
//	    seedDigest          OCTET STRING,
//	    workloadDigest      OCTET STRING
//	}
type configClaimsASN1V1 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
}

// configClaimsASN1V2 is the v2 DER encoding: v1 plus meshCADigest. Still
// parsed so certificates issued before allowlistDigest existed keep verifying.
//
//	C8SConfigClaims ::= SEQUENCE {
//	    version             INTEGER,
//	    operatorKeysDigest  OCTET STRING,
//	    seedDigest          OCTET STRING,
//	    workloadDigest      OCTET STRING,
//	    meshCADigest        OCTET STRING
//	}
type configClaimsASN1V2 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
	MeshCADigest       []byte
}

// configClaimsASN1 is the current (v3) encoding: v2 plus allowlistDigest.
//
//	C8SConfigClaims ::= SEQUENCE {
//	    version             INTEGER,
//	    operatorKeysDigest  OCTET STRING,
//	    seedDigest          OCTET STRING,
//	    workloadDigest      OCTET STRING,
//	    meshCADigest        OCTET STRING,
//	    allowlistDigest     OCTET STRING
//	}
//
// The version had to change rather than the field being appended optionally:
// UnmarshalConfigClaims requires a byte-exact round-trip, so any additional
// element is a different encoding by construction. That strictness is
// deliberate — it is what makes "parses as vN" mean "is the one vN encoding" —
// and it means a pre-v3 verifier rejects these claims outright instead of
// silently ignoring a field it cannot see. Fail closed, not fail quiet.
type configClaimsASN1 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
	MeshCADigest       []byte
	AllowlistDigest    []byte
}

// MarshalExtension encodes the claims as a DER-encoded X.509 extension.
// asn1.Marshal is deterministic, so the bytes the provider folds into
// REPORTDATA and the bytes CreateAttestedCert embeds are identical — the
// binding covers exactly what the certificate carries (docs/ratls.md).
func (c *ConfigClaims) MarshalExtension() (pkix.Extension, error) {
	for _, f := range []struct {
		name string
		d    []byte
	}{
		{"operator-keys", c.OperatorKeysDigest},
		{"seed", c.SeedDigest},
		{"workload", c.WorkloadDigest},
		{"mesh-ca", c.MeshCADigest},
		{"allowlist", c.AllowlistDigest},
	} {
		if len(f.d) != ClaimsDigestSize {
			return pkix.Extension{}, fmt.Errorf("ratls: %s claims digest must be %d bytes, got %d", f.name, ClaimsDigestSize, len(f.d))
		}
	}
	value, err := asn1.Marshal(configClaimsASN1{
		Version:            configClaimsVersion,
		OperatorKeysDigest: c.OperatorKeysDigest,
		SeedDigest:         c.SeedDigest,
		WorkloadDigest:     c.WorkloadDigest,
		MeshCADigest:       c.MeshCADigest,
		AllowlistDigest:    c.AllowlistDigest,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ratls: marshal config claims: %w", err)
	}
	return pkix.Extension{Id: OIDRATLSConfigClaims, Critical: false, Value: value}, nil
}

// UnmarshalConfigClaims decodes a DER-encoded config-claims extension value.
// It fails closed on an unknown version or a wrong-size digest: a verifier
// that cannot interpret the claims must not enforce policy against them
// (binding verification never needs to parse — docs/ratls.md).
func UnmarshalConfigClaims(der []byte) (*ConfigClaims, error) {
	// Peek at the version before choosing a shape: unmarshalling v1 bytes into
	// the v2 struct would fail on the missing element and vice versa, and the
	// resulting error should name the version, not the arity.
	var probe struct {
		Version int
		Rest    asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &probe); err != nil {
		return nil, fmt.Errorf("ratls: unmarshal config claims: %w", err)
	}

	switch probe.Version {
	case 3:
		var raw configClaimsASN1
		if err := unmarshalExact(der, &raw, 3); err != nil {
			return nil, err
		}
		claims := &ConfigClaims{
			OperatorKeysDigest: raw.OperatorKeysDigest,
			SeedDigest:         raw.SeedDigest,
			WorkloadDigest:     raw.WorkloadDigest,
			MeshCADigest:       raw.MeshCADigest,
			AllowlistDigest:    raw.AllowlistDigest,
		}
		if err := claims.validateDigests(); err != nil {
			return nil, err
		}
		return claims, nil

	case 2:
		// Pre-allowlistDigest certificates. The missing field reads as
		// UnsetDigest, so a verifier pinning a real live-allowlist digest can
		// never be satisfied by claims that never carried one.
		var raw configClaimsASN1V2
		if err := unmarshalExact(der, &raw, 2); err != nil {
			return nil, err
		}
		claims := &ConfigClaims{
			OperatorKeysDigest: raw.OperatorKeysDigest,
			SeedDigest:         raw.SeedDigest,
			WorkloadDigest:     raw.WorkloadDigest,
			MeshCADigest:       raw.MeshCADigest,
			AllowlistDigest:    UnsetDigest(),
		}
		if err := claims.validateDigests(); err != nil {
			return nil, err
		}
		return claims, nil

	case 1:
		// Pre-meshCADigest certificates. Accepted so an in-place CDS upgrade
		// does not invalidate leaves already issued; the missing field reads as
		// UnsetDigest, which a verifier pinning a real CA digest can never
		// match — so old claims cannot satisfy a new pin.
		var raw configClaimsASN1V1
		if err := unmarshalExact(der, &raw, 1); err != nil {
			return nil, err
		}
		claims := &ConfigClaims{
			OperatorKeysDigest: raw.OperatorKeysDigest,
			SeedDigest:         raw.SeedDigest,
			WorkloadDigest:     raw.WorkloadDigest,
			MeshCADigest:       UnsetDigest(),
			AllowlistDigest:    UnsetDigest(),
		}
		if err := claims.validateDigests(); err != nil {
			return nil, err
		}
		return claims, nil

	default:
		return nil, fmt.Errorf("ratls: unsupported config-claims version %d (supported: 1, 2, %d)", probe.Version, configClaimsVersion)
	}
}

// unmarshalExact decodes into v and requires the input to be the one canonical
// encoding of that shape. encoding/asn1 tolerates extra elements inside the
// SEQUENCE and non-minimal encodings; demanding a byte-exact round-trip keeps
// "parses as vN" equivalent to "is the one vN encoding", so no two distinct
// extension values can yield the same ConfigClaims — which matters because the
// REPORTDATA binding covers the raw bytes.
func unmarshalExact(der []byte, v any, version int) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return fmt.Errorf("ratls: unmarshal v%d config claims: %w", version, err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("ratls: %d trailing bytes after config-claims extension", len(rest))
	}
	// asn1.Marshal rejects pointers, and v must be one for Unmarshal — so
	// re-encode the pointed-to value.
	reencoded, err := asn1.Marshal(reflect.ValueOf(v).Elem().Interface())
	if err != nil {
		return fmt.Errorf("ratls: re-encode config claims: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return fmt.Errorf("ratls: config-claims extension is not the exact v%d encoding (%d bytes, canonical is %d)", version, len(der), len(reencoded))
	}
	return nil
}

// validateDigests rejects a claims set carrying a wrong-size digest. Applied
// after decoding so both versions share one rule.
func (c *ConfigClaims) validateDigests() error {
	for _, d := range [][]byte{c.OperatorKeysDigest, c.SeedDigest, c.WorkloadDigest, c.MeshCADigest, c.AllowlistDigest} {
		if len(d) != ClaimsDigestSize {
			return fmt.Errorf("ratls: config-claims digest is %d bytes, want %d", len(d), ClaimsDigestSize)
		}
	}
	return nil
}

// HasSeed reports whether the claims attest a configured allowlist seed.
func (c *ConfigClaims) HasSeed() bool {
	return !bytes.Equal(c.SeedDigest, unsetDigest)
}

// HasMeshCA reports whether the claims attest an issuing mesh CA. False on
// v1 claims, which predate the field.
func (c *ConfigClaims) HasMeshCA() bool {
	return !bytes.Equal(c.MeshCADigest, unsetDigest)
}

// HasAllowlist reports whether the claims attest a live allowlist digest.
// False on v1/v2 claims, which predate the field.
func (c *ConfigClaims) HasAllowlist() bool {
	return !bytes.Equal(c.AllowlistDigest, unsetDigest)
}

// HasWorkload reports whether the claims attest a workload digest.
func (c *ConfigClaims) HasWorkload() bool {
	return !bytes.Equal(c.WorkloadDigest, unsetDigest)
}

// ExtractConfigClaimsBytes returns the raw config-claims extension value from
// the certificate, or nil when the certificate carries none. The raw bytes are
// what the REPORTDATA preimage folds in — verification hashes exactly what the
// certificate carries, then parses only when claims semantics are needed.
func ExtractConfigClaimsBytes(cert *x509.Certificate) []byte {
	value, _ := configClaimsExtension(cert)
	return value
}

// configClaimsExtension returns the config-claims extension value and whether
// the extension is present at all. The distinction matters to VerifyCert: a
// present-but-empty extension is rejected there rather than silently treated
// as claims-free, so extension presence always implies a bound value.
func configClaimsExtension(cert *x509.Certificate) ([]byte, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDRATLSConfigClaims) {
			return ext.Value, true
		}
	}
	return nil, false
}
