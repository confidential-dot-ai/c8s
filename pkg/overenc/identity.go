package overenc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	identityTranscriptDomain = types.BindingAttestPQ
	// lbTranscriptDomain separates the attest-lb transcript from the attest-pq
	// one: the two endpoints sign different statements, so a response can
	// never be replayed across them.
	lbTranscriptDomain = types.BindingAttestLB
	identityNonceBytes = 32
)

// UpstreamIdentity is the plaintext destination both attestation transcripts
// commit: the canonical base URL the LB's forwarder dials ("" when it
// forwards nowhere), and for an https upstream the TLS verification server
// name and the SHA-256 of the CA bundle the peer is verified against
// (concatenated certificate DERs in file order). The zero value commits
// "forwards nowhere".
type UpstreamIdentity struct {
	URL        string
	ServerName string
	CAHash     []byte // SHA-256 (32 bytes); nil when the hop has no CA bundle
}

// UpstreamCABundleHash is the upstream_ca_sha256 commitment: SHA-256 over the
// concatenated DER of every CERTIFICATE block in a PEM bundle, in file order.
// A bundle with no CERTIFICATE blocks hashes to nil — "no CA bundle".
func UpstreamCABundleHash(pemBytes []byte) []byte {
	var concat []byte
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			concat = append(concat, block.Bytes...)
		}
	}
	if concat == nil {
		return nil
	}
	sum := sha256.Sum256(concat)
	return sum[:]
}

// upstreamFields frames the destination identity as the trailing transcript
// fields; a CA hash, when present, is exactly one SHA-256.
func upstreamFields(u UpstreamIdentity) ([][]byte, error) {
	if len(u.CAHash) != 0 && len(u.CAHash) != sha256.Size {
		return nil, fmt.Errorf("overenc: upstream CA hash must be %d bytes, got %d", sha256.Size, len(u.CAHash))
	}
	return [][]byte{[]byte(u.URL), []byte(u.ServerName), u.CAHash}, nil
}

// IdentityTranscriptHash commits the hybrid server key, client nonce, exact
// mesh leaf, issuing mesh CA, and upstream destination identity to one
// SHA-384 value suitable for TEE report_data:
//
//	SHA-384( LP("c8s/attest-pq/v2") || LP(SHA-256(mesh_CA_DER)) ||
//	         LP(SHA-256(mesh_leaf_DER)) || LP(x25519_pub) || LP(mlkem768_pub) ||
//	         LP(nonce) || LP(upstream) || LP(upstream_server_name) ||
//	         LP(upstream_ca_sha256) )
//
// Every variable-length field is length-prefixed to make the transcript
// unambiguous across the Go and browser implementations. The upstream triple
// is the destination the LB's forwarder dials (empty when it forwards
// nowhere); the client pins it out of band, so a control plane that repoints
// the front door changes the transcript, fails verification, and — the
// transcript being the channel's HKDF salt — cannot open a session record.
func IdentityTranscriptHash(pub PublicKey, nonce, leafDER, caDER []byte, upstream UpstreamIdentity) ([]byte, error) {
	if len(pub.X25519) != X25519PubBytes {
		return nil, fmt.Errorf("overenc: identity transcript X25519 key must be %d bytes, got %d", X25519PubBytes, len(pub.X25519))
	}
	if len(pub.MLKEM768) != MLKEM768EKBytes {
		return nil, fmt.Errorf("overenc: identity transcript ML-KEM key must be %d bytes, got %d", MLKEM768EKBytes, len(pub.MLKEM768))
	}
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: identity transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(leafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: identity transcript requires leaf and CA certificates")
	}

	leafHash := sha256.Sum256(leafDER)
	caHash := sha256.Sum256(caDER)
	fields := [][]byte{
		[]byte(identityTranscriptDomain),
		caHash[:],
		leafHash[:],
		pub.X25519,
		pub.MLKEM768,
		nonce,
	}
	destination, err := upstreamFields(upstream)
	if err != nil {
		return nil, err
	}
	fields = append(fields, destination...)
	var encoded []byte
	// Most-stable fields first so a signer can reuse the hash state across sessions.
	for _, field := range fields {
		var err error
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

// LBTranscriptHash commits the client nonce, exact outer serving leaf,
// exact mesh leaf, issuing mesh CA, and the upstream destination identity
// to one SHA-384 value suitable for TEE report_data — the attest-lb binding
// for clients that ride ordinary nginx TLS:
//
//	SHA-384( LP("c8s/attest-lb/v2") || LP(nonce) ||
//	         LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	         LP(SHA-256(mesh_CA_DER)) || LP(upstream) ||
//	         LP(upstream_server_name) || LP(upstream_ca_sha256) )
//
// A client recomputes it from the exact leaf it observed on the connection
// being authorized, so a response relayed through a different serving leaf
// fails even when both leaves share an issuer. The upstream triple is the
// destination the LB's forwarder dials (empty when it forwards nowhere); the
// client pins it out of band, so a control plane that repoints the front
// door changes the transcript and fails verification.
func LBTranscriptHash(nonce, servingLeafDER, meshLeafDER, caDER []byte, upstream UpstreamIdentity) ([]byte, error) {
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: lb transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(servingLeafDER) == 0 || len(meshLeafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: lb transcript requires serving leaf, mesh leaf, and CA certificates")
	}

	servingHash := sha256.Sum256(servingLeafDER)
	meshHash := sha256.Sum256(meshLeafDER)
	caHash := sha256.Sum256(caDER)
	fields := [][]byte{
		[]byte(lbTranscriptDomain),
		nonce,
		servingHash[:],
		meshHash[:],
		caHash[:],
	}
	destination, err := upstreamFields(upstream)
	if err != nil {
		return nil, err
	}
	fields = append(fields, destination...)
	var encoded []byte
	for _, field := range fields {
		var err error
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

// appendLengthPrefixed is the single owner of the transcript's LP(field) wire
// encoding (uint32_be length || field).
func appendLengthPrefixed(dst, field []byte) ([]byte, error) {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("overenc: identity transcript field is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	dst = append(dst, size[:]...)
	return append(dst, field...), nil
}
