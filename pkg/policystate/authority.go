package policystate

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// The authority is the Ed25519 key CDS signs state with. A verifier trusts a
// deployment by its fingerprint, so the protocol needs no epoch, no handoff
// and no key registry: a new authority key is a new authority.

// AuthorityFingerprint names a state-signing key by its DER SubjectPublicKeyInfo
// rather than by the raw 32 bytes, so the value matches what a verifier reads
// out of a certificate or a standard key file.
func AuthorityFingerprint(pub ed25519.PublicKey) (string, error) {
	der, err := authorityDER(pub)
	if err != nil {
		return "", err
	}
	return ContentDigest(der), nil
}

// EncodeAuthorityKey renders an authority key as unpadded base64url of its DER
// SubjectPublicKeyInfo, the wire form SignedState carries.
func EncodeAuthorityKey(pub ed25519.PublicKey) (string, error) {
	der, err := authorityDER(pub)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

// DecodeAuthorityKey parses the wire form produced by EncodeAuthorityKey and
// rejects anything that is not an Ed25519 key, so a peer cannot hand a
// verifier a key type it never meant to accept.
func DecodeAuthorityKey(s string) (ed25519.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("authority key is not unpadded base64url: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("authority key is not a DER SubjectPublicKeyInfo: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("authority key is %T, want ed25519", key)
	}
	return pub, nil
}

// authorityDER marshals a public key, checking its length first: x509 accepts
// an ed25519.PublicKey of any size and would fingerprint a truncated key.
func authorityDER(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("authority key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("authority key: %w", err)
	}
	return der, nil
}
