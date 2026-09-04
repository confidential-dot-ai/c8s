// Static allowlist: the canonical digest of the one allowlist document a
// sealed-policy CDS enforces for its whole lifetime, stamped by CDS as an
// X.509 extension on its own mesh CA certificate (docs/static-allowlist.md).
//
// Unlike the matched-workload stamp on a leaf, this extension rides the CA
// certificate itself, and the CA certificate's SHA-256 is already committed
// into the fresh, client-nonce-bound REPORTDATA of every attest-pq/attest-lb
// response (pkg/overenc). A sealed CA also embeds its own RA-TLS attestation
// extension over the CA public key, so a verifier holding the expected
// canonical allowlist digest can check, per request: this connection ends at
// a key vouched by a CA that was born inside a measured CDS launched to
// enforce exactly that policy.
//
// The extension value alone is CA-self-asserted. What makes it more than a
// claim is the pairing: the embedded CA evidence proves the CA key was born
// in a pinned CDS launch, and a sealed CDS refuses to start (and to serve or
// mutate any other policy) unless the digest it stamps is the digest of the
// document it loaded. Verifiers must require both — the stamp and the CA
// evidence — before treating the digest as enforced (docs/static-allowlist.md,
// "What the verifier checks").

package ratls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// OIDStaticAllowlist identifies the static-allowlist extension (see
// extension.go for the 1.3.6.1.4.1.66378 arc):
//
//	1.3.6.1.4.1.66378.1.3 - static allowlist extension
var OIDStaticAllowlist = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 3}

// staticAllowlistVersion is the only encoding version this package emits or
// parses. An unknown version fails closed wherever the sealed policy is read.
const staticAllowlistVersion = 1

// StaticAllowlist is the sealed-policy stamp on a mesh CA certificate.
type StaticAllowlist struct {
	// AllowlistDigest is SHA-256 of Allowlist.Canonical() of the one document
	// this CDS enforces for its lifetime, exactly 32 bytes.
	AllowlistDigest []byte
}

// staticAllowlistASN1 is the DER encoding:
//
//	StaticAllowlist ::= SEQUENCE {
//	    formatVersion    INTEGER,           -- exactly 1
//	    allowlistDigest  OCTET STRING (32)  -- SHA-256(Allowlist.Canonical())
//	}
type staticAllowlistASN1 struct {
	FormatVersion   int
	AllowlistDigest []byte
}

// Validate rejects a value this package must neither emit nor accept.
func (s *StaticAllowlist) Validate() error {
	if len(s.AllowlistDigest) != allowlistDigestSize {
		return fmt.Errorf("ratls: static-allowlist digest must be %d bytes, got %d", allowlistDigestSize, len(s.AllowlistDigest))
	}
	return nil
}

// MarshalStaticAllowlistExtension encodes s as the non-critical
// static-allowlist extension.
func MarshalStaticAllowlistExtension(s *StaticAllowlist) (pkix.Extension, error) {
	if err := s.Validate(); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(staticAllowlistASN1{
		FormatVersion:   staticAllowlistVersion,
		AllowlistDigest: s.AllowlistDigest,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ratls: marshal static allowlist: %w", err)
	}
	return pkix.Extension{Id: OIDStaticAllowlist, Value: value}, nil
}

// UnmarshalStaticAllowlist decodes a DER-encoded static-allowlist extension
// value, requiring the one canonical encoding: minimal DER, no trailing bytes
// or fields, byte-exact against re-encoding — no two distinct extension values
// may parse to the same StaticAllowlist.
func UnmarshalStaticAllowlist(der []byte) (*StaticAllowlist, error) {
	var raw staticAllowlistASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: unmarshal static allowlist: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ratls: %d trailing bytes after static-allowlist extension", len(rest))
	}
	if raw.FormatVersion != staticAllowlistVersion {
		return nil, fmt.Errorf("ratls: unsupported static-allowlist version %d (supported: %d)", raw.FormatVersion, staticAllowlistVersion)
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: re-encode static allowlist: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("ratls: static-allowlist extension is not the exact v%d encoding (%d bytes, canonical is %d)", staticAllowlistVersion, len(der), len(reencoded))
	}
	s := &StaticAllowlist{AllowlistDigest: raw.AllowlistDigest}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// StaticAllowlistFromCert returns the certificate's static-allowlist stamp, or
// nil when the certificate carries none. A present but malformed or duplicated
// extension is an error, never nil — a verifier must not read damage as
// absence.
func StaticAllowlistFromCert(cert *x509.Certificate) (*StaticAllowlist, error) {
	var found *StaticAllowlist
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDStaticAllowlist) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ratls: certificate carries more than one static-allowlist extension")
		}
		s, err := UnmarshalStaticAllowlist(ext.Value)
		if err != nil {
			return nil, err
		}
		found = s
	}
	return found, nil
}
