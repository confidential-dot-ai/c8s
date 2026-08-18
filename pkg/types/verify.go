package types

import "encoding/json"

// Browser-facing attestation + over-encryption wire types for the c8s-verify
// protocol served by the Load Balancer. These mirror c8s-verify-js/PROTOCOL.md
// and are consumed by the JavaScript client (c8s-verify-js) and any other
// out-of-cluster verifier. All *_pubkey / handshake byte fields are base64url
// (unpadded); the evidence sub-fields follow the platform's attestation-rs
// evidence shape (SnpEvidence uses standard base64; see PROTOCOL.md for the
// per-platform encodings).

// SessionPublicKey is the LB's per-session hybrid (X25519 + ML-KEM-768) public
// key, committed by the report_data transcript.
type SessionPublicKey struct {
	X25519   string `json:"x25519"`   // base64url, 32 bytes
	MLKEM768 string `json:"mlkem768"` // base64url, 1184 bytes
}

const (
	// BindingAttestPQ / BindingAttestLB are the response binding identifiers
	// carried in AttestationBundle.Version by the two explicit attestation
	// endpoints, and the transcript domain tags overenc.IdentityTranscriptHash
	// / overenc.LBTranscriptHash frame into report_data. A client requires
	// the identifier selected by its endpoint mode and rejects the other
	// response shape even if its evidence is otherwise valid — there is no
	// negotiation, alias, or fallback.
	BindingAttestPQ = "c8s/attest-pq/v2"
	BindingAttestLB = "c8s/attest-lb/v2"

	// MeshIdentityProofECDSASHA384 is the proof-of-possession algorithm.
	MeshIdentityProofECDSASHA384 = "ecdsa-sha384"
)

// MeshIdentityProof authenticates the PQ session transcript with the private
// key corresponding to the mesh leaf in AttestationBundle.CDSCertPEM. Hashes
// are unpadded base64url SHA-256; Signature is unpadded base64url ASN.1 DER
// ECDSA (minimal DER, as emitted by ecdsa.SignASN1 — the JS verifier rejects
// redundant integer padding).
type MeshIdentityProof struct {
	Algorithm    string `json:"algorithm"`      // MeshIdentityProofECDSASHA384
	LeafSHA256   string `json:"leaf_sha256"`    // base64url; exact leaf DER committed by report_data
	MeshCASHA256 string `json:"mesh_ca_sha256"` // base64url; issuing CA DER committed by report_data
	Signature    string `json:"signature"`      // base64url ASN.1 DER ECDSA signature
}

// AttestationBundle is the response body of the two explicit attestation
// endpoints, GET /.well-known/c8s/attest-pq?nonce=<b64url> and
// GET /.well-known/c8s/attest-lb?nonce=<b64url>. attest-pq binds report_data
// to the per-session hybrid key, the mesh identity, and the upstream
// destination identity (overenc.IdentityTranscriptHash); attest-lb binds it
// to the exact outer serving leaf, the mesh identity, and the same upstream
// destination identity (overenc.LBTranscriptHash) for native clients that
// ride ordinary nginx TLS. Version carries the endpoint's binding identifier
// (BindingAttestPQ / BindingAttestLB); a client requires the one its endpoint
// mode selects.
type AttestationBundle struct {
	Version    string          `json:"version"`      // BindingAttestPQ | BindingAttestLB
	Platform   string          `json:"platform"`     // "snp" | "az-snp" | "az-tdx" | "tdx"
	Generation string          `json:"generation"`   // AMD gen for "snp": milan|genoa|turin; empty otherwise
	Nonce      string          `json:"nonce"`        // echoed client nonce (b64url)
	Evidence   json.RawMessage `json:"evidence"`     // platform-shaped attestation-rs evidence
	CDSCertPEM string          `json:"cds_cert_pem"` // exact mesh leaf + issuing CA committed by report_data
	// SessionPubKey is the per-session over-encryption key, present only for
	// the attest-pq response; attest-lb creates no session.
	SessionPubKey *SessionPublicKey `json:"session_pubkey,omitempty"`
	// IdentityProof proves possession of the mesh leaf committed by
	// report_data, over the endpoint's transcript.
	IdentityProof *MeshIdentityProof `json:"identity_proof,omitempty"`
	// ServingLeafSHA256 (attest-lb only) is the unpadded base64url SHA-256 of
	// the serving-leaf DER the sidecar committed into report_data.
	// Informational: the client MUST recompute this hash from the leaf it
	// observed on its own TLS connection and verify the transcript with that
	// value — trusting the served field would let a relay substitute the leaf.
	ServingLeafSHA256 string `json:"serving_leaf_sha256,omitempty"`
	// Upstream is the canonical upstream base URL the sidecar committed into
	// report_data — the destination its own forwarding dials (empty in the
	// deliberate attestation-only echo mode, and always serialized so a
	// committed-empty destination reads as a choice, not an absence).
	// Informational: the client MUST verify the transcript against its own
	// out-of-band pinned destination and treat a mismatch with this served
	// field as fatal — trusting the served value would let the control plane
	// name any destination.
	Upstream string `json:"upstream"`
	// UpstreamServerName is the TLS verification name the sidecar uses for an
	// https upstream, committed into report_data alongside Upstream; it
	// serializes empty for a plaintext (mesh-wrapped) upstream.
	// Informational, same MUST-pin contract as Upstream.
	UpstreamServerName string `json:"upstream_server_name"`
	// UpstreamCASHA256 is the unpadded base64url SHA-256 of the upstream CA
	// bundle the sidecar verifies an https upstream against (concatenated
	// certificate DERs in file order), committed into report_data alongside
	// Upstream; it serializes empty for a plaintext upstream. Informational,
	// same MUST-pin contract as Upstream.
	UpstreamCASHA256 string `json:"upstream_ca_sha256"`
}

// HandshakeRequest is the body of POST /.well-known/c8s/handshake: the client
// commits to a nonce (selecting the LB's stored session key) and supplies its
// hybrid handshake material.
type HandshakeRequest struct {
	Nonce        string `json:"nonce"`         // b64url, selects the pending session
	ClientX25519 string `json:"client_x25519"` // b64url, 32 bytes
	MLKEMCt      string `json:"mlkem_ct"`      // b64url, 1088 bytes
}

// HandshakeResponse returns the established session identifier.
type HandshakeResponse struct {
	SessionID string `json:"session_id"`
}

// TunnelRequest is the plaintext application request carried inside an
// over-encrypted record sent to POST /.well-known/c8s/tunnel. The whole request
// — method, path, headers, and body — is sealed, so a TLS-terminating proxy in
// front of the LB sees only ciphertext. The sidecar decrypts it and forwards the
// reconstructed request as plaintext to the backend (the cluster raTLS mesh wraps
// that hop).
type TunnelRequest struct {
	Method  string            `cbor:"method" json:"method"`
	Path    string            `cbor:"path" json:"path"`
	Headers map[string]string `cbor:"headers,omitempty" json:"headers,omitempty"`
	Body    []byte            `cbor:"body,omitempty" json:"body,omitempty"` // raw body, CBOR byte string
}

// TunnelResponse is the backend response, sealed back to the client.
type TunnelResponse struct {
	Status  int               `cbor:"status" json:"status"`
	Headers map[string]string `cbor:"headers,omitempty" json:"headers,omitempty"`
	Body    []byte            `cbor:"body,omitempty" json:"body,omitempty"` // raw body, CBOR byte string
}
