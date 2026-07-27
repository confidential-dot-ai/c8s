// Package secrets carries the wire contract between the CDS secrets broker
// and its clients (the c8s-secrets init container, the operator CLI): request
// and response types, the attestation transcript, the response wrap, and the
// broker-identity document. The broker itself lives in internal/cmds/cds; the
// store interface in internal/secretstore. See docs/secrets-broker.md.
package secrets

import (
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// SecretRequest asks for the values at the given paths on behalf of one
// container digest. Grants are resolved per (entry, digest, path) at CDS.
type SecretRequest struct {
	Digest string   `json:"digest"`
	Paths  []string `json:"paths"`
}

// FetchRequest is the body of POST /secrets/fetch. The init/main digest lists
// are the pod's claimed non-injected container set (the webhook passes them
// from the digest-pinned pod spec); CDS resolves them to exactly one workload
// entry and grants only that entry's per-digest paths.
type FetchRequest struct {
	Challenge string                    `json:"challenge"`
	Evidence  types.AttestationEvidence `json:"evidence"`

	InitContainerDigests []string `json:"init_container_digests,omitempty"`
	ContainerDigests     []string `json:"container_digests,omitempty"`

	// ResponsePubkey is the standard-base64 raw X25519 public key the
	// response is wrapped to. It rides the attestation transcript, so a
	// relay cannot swap it without failing evidence verification.
	ResponsePubkey string `json:"response_pubkey"`

	Requests []SecretRequest `json:"requests"`
}

// FetchResponse is the success body of POST /secrets/fetch. Payload is the
// wrapped canonical JSON of map[path]base64(value); Signature is the broker
// signing leaf's ECDSA over it. Clients verify the signature against the
// broker identity (which chains to the mesh CA) before unwrapping.
type FetchResponse struct {
	Payload   Wrapped `json:"payload"`
	Signature string  `json:"signature"`
}

// Wrapped is a one-shot X25519 + HKDF-SHA256 + AES-256-GCM sealed message:
// the sender's ephemeral public key, the nonce, and the ciphertext. See wrap.go.
type Wrapped struct {
	EphemeralPubkey string `json:"ephemeral_pubkey"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// BrokerIdentity is served at GET /secrets/broker-identity. It proves the
// endpoint holds the mesh CA key (the one secret a same-measurement fake CDS
// lacks): the signing leaf chains to the mesh CA, and the encryption pubkey is
// bound to the leaf by signature. See docs/secrets-broker.md.
type BrokerIdentity struct {
	// SigningLeafPEM is the broker's ECDSA P-384 leaf issued by the mesh CA.
	SigningLeafPEM []byte `json:"signing_leaf_pem"`
	// CAChainPEM is the mesh CA chain the leaf verifies against.
	CAChainPEM []byte `json:"ca_chain_pem"`
	// EncryptionPubkey is the standard-base64 raw X25519 public key deposit
	// values are wrapped to.
	EncryptionPubkey string `json:"encryption_pubkey"`
	// EncryptionPubkeySig is the standard-base64 ECDSA signature by the
	// signing leaf over the encryption pubkey (domain-separated, identity.go).
	EncryptionPubkeySig string `json:"encryption_pubkey_signature"`
}
