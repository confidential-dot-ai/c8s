package policystate

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Sign returns the base64url signature over domain || 0x00 || canonical.
// Ed25519 hashes its own input, so there is no pre-hash to get wrong and the
// verifier always sees the bytes the signer meant.
func Sign(priv ed25519.PrivateKey, domain string, canonical []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("sign: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(priv, signedBytes(domain, canonical))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks a base64url signature produced by Sign.
func Verify(pub ed25519.PublicKey, domain string, canonical []byte, signature string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("verify: signature is not unpadded base64url: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("verify: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, signedBytes(domain, canonical), sig) {
		return fmt.Errorf("verify: signature does not verify under domain %q", domain)
	}
	return nil
}

func signedBytes(domain string, canonical []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(canonical))
	out = append(out, domain...)
	out = append(out, 0)
	return append(out, canonical...)
}

// Envelope is a signed protocol message: the message itself plus a detached
// signature over its canonical bytes. It is the shape every participant
// message (Enrollment, Ack, Completion) is posted in.
type Envelope[T any] struct {
	Message   T      `json:"message"`
	Signature string `json:"signature"`
}

// SignMessage canonicalizes msg and wraps it with a signature under domain.
func SignMessage[T any](priv ed25519.PrivateKey, domain string, msg T) (Envelope[T], error) {
	canonical, err := Canonical(msg)
	if err != nil {
		return Envelope[T]{}, err
	}
	sig, err := Sign(priv, domain, canonical)
	if err != nil {
		return Envelope[T]{}, err
	}
	return Envelope[T]{Message: msg, Signature: sig}, nil
}

// VerifyMessage checks an Envelope against pub. It re-canonicalizes the
// decoded message rather than trusting the bytes received, so a sender cannot
// get one document signed and another one parsed.
func VerifyMessage[T any](pub ed25519.PublicKey, domain string, env Envelope[T]) error {
	canonical, err := Canonical(env.Message)
	if err != nil {
		return err
	}
	return Verify(pub, domain, canonical, env.Signature)
}
