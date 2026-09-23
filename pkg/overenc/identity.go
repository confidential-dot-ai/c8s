package overenc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
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

// IdentityTranscriptHash commits the front-door mode, the complete key
// exchange — the client's X-Wing encapsulation key, the server's ciphertext,
// the session id, and the client nonce — the exact mesh leaf and issuing mesh
// CA, and the policy the session runs under, to one SHA-384 value suitable
// for TEE report_data:
//
//	SHA-384( LP("c8s-verify/v1") || LP(mode) || LP(SHA-256(ca_DER)) ||
//	         LP(SHA-256(leaf_DER)) || LP(xwing_ek) || LP(xwing_ct) ||
//	         LP(session_id) || LP(nonce) ||
//	         LP(state_hash) || LP(envelope_json) || LP(route) )
//
// The evidence therefore covers both sides of the exchange, not only the
// server's contribution. Every variable-length field is length-prefixed to
// make the transcript unambiguous across the Go and browser implementations.
//
// stateHash is policystate.StateHash(S) as its "sha256:<hex>" string bytes —
// the text form, not the decoded digest — so a verifier compares what it
// prints. envelope is policystate.Bound(S), framed as the JSON array of those
// strings (see [EncodeEnvelope]): it is the fixed set of policy digests this
// session may operate under, so a later state whose bound is a subset of it
// does not retire the session. route names the workload the router forwards
// this session to, and is length-prefixed even when empty, so "no route
// configured" is a field rather than a shorter transcript.
//
// The binding proves which statement the router used, not that the statement
// is current: only a CDS challenge bound to the verifier's own nonce does
// that (docs/ratls.md, "State binding").
func IdentityTranscriptHash(mode types.FrontDoorMode, xwingEK, xwingCT, sessionID, nonce, leafDER, caDER []byte, stateHash string, envelope []string, route string) ([]byte, error) {
	fields, err := identityFields(mode, xwingEK, xwingCT, sessionID, nonce, leafDER, caDER)
	if err != nil {
		return nil, err
	}
	if stateHash == "" {
		return nil, fmt.Errorf("overenc: identity transcript requires a state hash")
	}
	encodedEnvelope, err := EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return hashFields(identityTranscriptDomain, append(fields, []byte(stateHash), encodedEnvelope, []byte(route)))
}

// EncodeEnvelope renders a session's policy envelope as the exact bytes the
// transcript frames: the JSON array of the digest strings, in the order
// policystate.Bound produced them. It is exported so a responder and a
// verifier agree on those bytes without either re-deriving the encoding.
func EncodeEnvelope(envelope []string) ([]byte, error) {
	if len(envelope) == 0 {
		return nil, fmt.Errorf("overenc: identity transcript requires a policy envelope")
	}
	for _, digest := range envelope {
		if digest == "" {
			return nil, fmt.Errorf("overenc: identity transcript envelope has an empty digest")
		}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("overenc: encode identity transcript envelope: %w", err)
	}
	return encoded, nil
}

// identityFields is the attest-pq transcript body: everything the transcript
// commits before the policy binding.
func identityFields(mode types.FrontDoorMode, xwingEK, xwingCT, sessionID, nonce, leafDER, caDER []byte) ([][]byte, error) {
	if mode == "" {
		return nil, fmt.Errorf("overenc: identity transcript requires a front-door mode")
	}
	if len(xwingEK) != XWingEKBytes {
		return nil, fmt.Errorf("overenc: identity transcript X-Wing key must be %d bytes, got %d", XWingEKBytes, len(xwingEK))
	}
	if len(xwingCT) != XWingCTBytes {
		return nil, fmt.Errorf("overenc: identity transcript X-Wing ciphertext must be %d bytes, got %d", XWingCTBytes, len(xwingCT))
	}
	if len(sessionID) != SessionIDBytes {
		return nil, fmt.Errorf("overenc: identity transcript session id must be %d bytes, got %d", SessionIDBytes, len(sessionID))
	}
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: identity transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(leafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: identity transcript requires leaf and CA certificates")
	}

	leafHash := sha256.Sum256(leafDER)
	caHash := sha256.Sum256(caDER)
	// Most-stable fields first so a signer can reuse the hash state across sessions.
	return [][]byte{
		[]byte(mode),
		caHash[:],
		leafHash[:],
		xwingEK,
		xwingCT,
		sessionID,
		nonce,
	}, nil
}

// LBTranscriptHash commits the front-door mode, client nonce, exact outer
// serving leaf, exact mesh leaf, and issuing mesh CA to one SHA-384 value
// suitable for TEE report_data — the attest-lb binding for clients that ride
// ordinary nginx TLS:
//
//	SHA-384( LP("c8s/attest-lb/v1") || LP(mode) || LP(nonce) ||
//	         LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	         LP(SHA-256(mesh_CA_DER)) )
//
// A client recomputes it from the exact leaf it observed on the connection
// being authorized, so a response relayed through a different serving leaf
// fails even when both leaves share an issuer.
func LBTranscriptHash(mode types.FrontDoorMode, nonce, servingLeafDER, meshLeafDER, caDER []byte) ([]byte, error) {
	fields, err := lbFields(mode, nonce, servingLeafDER, meshLeafDER, caDER)
	if err != nil {
		return nil, err
	}
	return hashFields(lbTranscriptDomain, fields)
}

// lbFields is the attest-lb transcript body.
func lbFields(mode types.FrontDoorMode, nonce, servingLeafDER, meshLeafDER, caDER []byte) ([][]byte, error) {
	if mode == "" {
		return nil, fmt.Errorf("overenc: lb transcript requires a front-door mode")
	}
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: lb transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(servingLeafDER) == 0 || len(meshLeafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: lb transcript requires serving leaf, mesh leaf, and CA certificates")
	}

	servingHash := sha256.Sum256(servingLeafDER)
	meshHash := sha256.Sum256(meshLeafDER)
	caHash := sha256.Sum256(caDER)
	return [][]byte{
		[]byte(mode),
		nonce,
		servingHash[:],
		meshHash[:],
		caHash[:],
	}, nil
}

// hashFields frames domain and fields as LP(domain) || LP(field)… and hashes
// the result, the one place either transcript's SHA-384 is taken.
func hashFields(domain string, fields [][]byte) ([]byte, error) {
	encoded, err := appendLengthPrefixed(nil, []byte(domain))
	if err != nil {
		return nil, err
	}
	for _, field := range fields {
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
