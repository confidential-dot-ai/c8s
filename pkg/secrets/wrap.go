package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// wrapHKDFInfo domain-separates the key derivation. Bump with the wire version.
const wrapHKDFInfo = "c8s/secrets-wrap/v1"

// FetchAAD binds a wrapped fetch payload to the fetch flow.
const FetchAAD = "c8s/secrets-fetch-response/v1"

// DepositAAD binds a wrapped operator deposit to its destination ref.
func DepositAAD(entry, path string) []byte {
	return []byte("c8s/secrets-deposit/v1\x00" + entry + "\x00" + path)
}

// Wrap seals plaintext to a recipient's raw X25519 public key with a fresh
// ephemeral key: ECDH(ephemeral, recipient) → HKDF-SHA256 → AES-256-GCM. The
// construction mirrors pkg/overenc's channel derivation, shrunk to one shot.
// AAD binds the ciphertext to purpose, so a blob cut from one flow cannot be
// replayed into another.
func Wrap(recipientPub, plaintext, aad []byte) (Wrapped, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: parse recipient key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: generate ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: ECDH: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: nonce: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nonce, wrapHKDFInfo, 32)
	if err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: HKDF: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Wrapped{}, fmt.Errorf("secrets wrap: GCM: %w", err)
	}
	return Wrapped{
		EphemeralPubkey: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, aad)),
	}, nil
}

// Unwrap opens a Wrapped blob with the recipient's raw X25519 private key.
func Unwrap(recipientPriv, aad []byte, blob Wrapped) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: parse private key: %w", err)
	}
	ephPubBytes, err := base64.StdEncoding.DecodeString(blob.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: ephemeral key: %w", err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: parse ephemeral key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: ciphertext: %w", err)
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: ECDH: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nonce, wrapHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: HKDF: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: GCM: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("secrets unwrap: open: %w", err)
	}
	return plaintext, nil
}

// GenerateX25519 returns a fresh raw (private, public) key pair.
func GenerateX25519() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("secrets: generate X25519 key: %w", err)
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}
