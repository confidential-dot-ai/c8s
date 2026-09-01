package overenc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	identityTranscriptDomain = types.ProtocolVersion
	// lbTranscriptDomain separates the attest-lb transcript from the attest-pq
	// one: the two endpoints sign different statements, so a response can
	// never be replayed across them.
	lbTranscriptDomain = types.BindingAttestLB
	// operatorKeySetTranscriptDomain separates the active operator-policy
	// commitment from both endpoint transcript formats. The value committed is
	// operatorauth.KeySetHash: a canonical, framed commitment to the complete
	// active key set. It is not an individual operator-key fingerprint.
	operatorKeySetTranscriptDomain = "c8s/operator-key-set/v1"
	identityNonceBytes             = 32
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
// exact mesh leaf, and issuing mesh CA to one SHA-384 value suitable for TEE
// report_data — the attest-lb binding for clients that ride ordinary nginx
// TLS:
//
//	SHA-384( LP("c8s/attest-lb/v1") || LP(nonce) ||
//	         LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	         LP(SHA-256(mesh_CA_DER)) )
//
// A client recomputes it from the exact leaf it observed on the connection
// being authorized, so a response relayed through a different serving leaf
// fails even when both leaves share an issuer.
func LBTranscriptHash(nonce, servingLeafDER, meshLeafDER, caDER []byte) ([]byte, error) {
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
	} {
		var err error
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

// BindOperatorKeySetHash adds the active operator key-set commitment to an
// endpoint transcript. Empty keySetHash preserves the old transcript for
// deployments that do not expose active operator policy. A non-empty value
// must be the canonical lowercase SHA-256 value returned by
// operatorauth.KeySetHash.
func BindOperatorKeySetHash(transcriptHash []byte, keySetHash string) ([]byte, error) {
	if len(transcriptHash) != sha512.Size384 {
		return nil, fmt.Errorf("overenc: transcript hash must be %d bytes, got %d", sha512.Size384, len(transcriptHash))
	}
	if keySetHash == "" {
		return append([]byte(nil), transcriptHash...), nil
	}
	keySetDigest, err := hex.DecodeString(keySetHash)
	if err != nil || len(keySetDigest) != sha256.Size || keySetHash != lowerASCII(keySetHash) {
		return nil, fmt.Errorf("overenc: operator key-set hash must be %d lowercase hex characters", sha256.Size*2)
	}
	var encoded []byte
	for _, field := range [][]byte{
		[]byte(operatorKeySetTranscriptDomain),
		transcriptHash,
		keySetDigest,
	} {
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

func lowerASCII(value string) string {
	b := []byte(value)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
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
