package secrets

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// Domain separators for the broker-identity binding signature and response
// signatures. Bump with the wire version.
const (
	encBindingDomainSep  = "c8s/secrets-broker-enc/v1\x00"
	responseSigDomainSep = "c8s/secrets-response/v1\x00"
)

// SignEncryptionPubkey produces the binding signature a broker signing key
// makes over its encryption pubkey, proving the CA-issued leaf endorses this
// encryption key.
func SignEncryptionPubkey(signingPriv *ecdsa.PrivateKey, encPub []byte) (string, error) {
	digest := sha512.Sum384(append([]byte(encBindingDomainSep), encPub...))
	sig, err := ecdsa.SignASN1(rand.Reader, signingPriv, digest[:])
	if err != nil {
		return "", fmt.Errorf("secrets identity: sign encryption pubkey: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks the broker identity's chain to a mesh CA root and returns the
// verified (signing, encryption) public keys.
func (bi BrokerIdentity) Verify(caRoots *x509.CertPool) (*ecdsa.PublicKey, []byte, error) {
	leaf, err := parseOneCert(bi.SigningLeafPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("secrets identity: parse signing leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for block, rest := pem.Decode(bi.CAChainPEM); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("secrets identity: parse CA chain: %w", err)
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: caRoots, Intermediates: intermediates}); err != nil {
		return nil, nil, fmt.Errorf("secrets identity: signing leaf does not chain to the mesh CA: %w", err)
	}
	signingPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("secrets identity: signing leaf is not ECDSA")
	}

	encPub, err := base64.StdEncoding.DecodeString(bi.EncryptionPubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("secrets identity: encryption pubkey: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(bi.EncryptionPubkeySig)
	if err != nil {
		return nil, nil, fmt.Errorf("secrets identity: encryption pubkey signature: %w", err)
	}
	digest := sha512.Sum384(append([]byte(encBindingDomainSep), encPub...))
	if !ecdsa.VerifyASN1(signingPub, digest[:], sig) {
		return nil, nil, errors.New("secrets identity: encryption pubkey not bound to the signing leaf")
	}
	return signingPub, encPub, nil
}

// SignResponse signs a wrapped fetch payload with the broker signing key.
func SignResponse(signingPriv *ecdsa.PrivateKey, payload Wrapped) (string, error) {
	digest := responseDigest(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, signingPriv, digest[:])
	if err != nil {
		return "", fmt.Errorf("secrets: sign response: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyResponseSignature checks a fetch response signature. It deliberately
// does not verify the payload contents — that is Unwrap's job, and it only
// succeeds for the holder of the request key.
func VerifyResponseSignature(signingPub *ecdsa.PublicKey, payload Wrapped, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("secrets: response signature encoding: %w", err)
	}
	digest := responseDigest(payload)
	if !ecdsa.VerifyASN1(signingPub, digest[:], sig) {
		return errors.New("secrets: response signature invalid")
	}
	return nil
}

func responseDigest(payload Wrapped) [48]byte {
	return sha512.Sum384([]byte(responseSigDomainSep + payload.EphemeralPubkey + payload.Nonce + payload.Ciphertext))
}

func parseOneCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}
