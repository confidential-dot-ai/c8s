package overenc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	identityTranscriptDomain = types.ProtocolVersion
	// lbTranscriptDomain separates the attest-lb transcript from the attest-pq
	// one: the two endpoints sign different statements, so a response can
	// never be replayed across them.
	lbTranscriptDomain = types.BindingAttestLB
	identityNonceBytes = 32
)

// IdentityTranscriptHash commits the hybrid server key, client nonce, exact
// mesh leaf, and issuing mesh CA to one SHA-384 value suitable for TEE
// report_data. Every variable-length field is length-prefixed to make the
// transcript unambiguous across the Go and browser implementations.
func IdentityTranscriptHash(pub PublicKey, nonce, leafDER, caDER []byte) ([]byte, error) {
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
	var encoded []byte
	// Most-stable fields first so a signer can reuse the hash state across sessions.
	for _, field := range [][]byte{
		[]byte(identityTranscriptDomain),
		caHash[:],
		leafHash[:],
		pub.X25519,
		pub.MLKEM768,
		nonce,
	} {
		var err error
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

// LBTranscriptHash commits the client nonce, exact outer serving leaf,
// exact mesh leaf, issuing mesh CA, and the configured upstream destination
// to one SHA-384 value suitable for TEE report_data — the attest-lb binding
// for clients that ride ordinary nginx TLS:
//
//	SHA-384( LP("c8s/attest-lb/v2") || LP(nonce) ||
//	         LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	         LP(SHA-256(mesh_CA_DER)) || LP(upstream) )
//
// A client recomputes it from the exact leaf it observed on the connection
// being authorized, so a response relayed through a different serving leaf
// fails even when both leaves share an issuer. upstream is the canonical base
// URL the LB forwards decrypted traffic to (empty when it forwards nowhere);
// the client pins it out of band, so a control plane that repoints the front
// door changes the transcript and fails verification.
func LBTranscriptHash(nonce, servingLeafDER, meshLeafDER, caDER []byte, upstream string) ([]byte, error) {
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: lb transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(servingLeafDER) == 0 || len(meshLeafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: lb transcript requires serving leaf, mesh leaf, and CA certificates")
	}

	servingHash := sha256.Sum256(servingLeafDER)
	meshHash := sha256.Sum256(meshLeafDER)
	caHash := sha256.Sum256(caDER)
	var encoded []byte
	for _, field := range [][]byte{
		[]byte(lbTranscriptDomain),
		nonce,
		servingHash[:],
		meshHash[:],
		caHash[:],
		[]byte(upstream),
	} {
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
