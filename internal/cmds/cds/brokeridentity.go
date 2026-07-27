package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/secrets"
)

// brokerIdentity holds the CDS's secrets-broker identity: an ECDSA signing
// leaf issued by the mesh CA and an X25519 encryption key bound to that leaf.
// A same-measurement fake CDS can copy config, but it cannot hold the mesh CA
// key, so it cannot mint this identity — clients that verify it defuse fake
// and relay CDSes (docs/secrets-broker.md).
type brokerIdentity struct {
	doc        secrets.BrokerIdentity
	signingKey *ecdsa.PrivateKey
	encPriv    []byte
}

// newBrokerIdentity issues the broker identity from the mesh CA. The leaf
// lives only in process memory and dies with the CA on restart, so its TTL is
// capped by the CA's own lifetime.
func newBrokerIdentity(ca *issuer.CA, caChainPEM []byte) (*brokerIdentity, error) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("broker identity: generate signing key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "c8s-secrets-broker"},
	}, signingKey)
	if err != nil {
		return nil, fmt.Errorf("broker identity: create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("broker identity: parse CSR: %w", err)
	}
	ttl := time.Until(ca.Cert.NotAfter)
	if ttl <= 0 {
		return nil, fmt.Errorf("broker identity: mesh CA already expired")
	}
	leafPEM, _, err := ca.SignCSR(issuer.SignCSRParams{CSR: csr, TTL: ttl})
	if err != nil {
		return nil, fmt.Errorf("broker identity: sign leaf: %w", err)
	}

	encPriv, encPub, err := secrets.GenerateX25519()
	if err != nil {
		return nil, err
	}
	encSig, err := secrets.SignEncryptionPubkey(signingKey, encPub)
	if err != nil {
		return nil, err
	}

	return &brokerIdentity{
		doc: secrets.BrokerIdentity{
			SigningLeafPEM:      leafPEM,
			CAChainPEM:          caChainPEM,
			EncryptionPubkey:    base64.StdEncoding.EncodeToString(encPub),
			EncryptionPubkeySig: encSig,
		},
		signingKey: signingKey,
		encPriv:    encPriv,
	}, nil
}
