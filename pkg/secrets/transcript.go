package secrets

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fetchDomainSep domain-separates the fetch transcript. Bump with the wire version.
const fetchDomainSep = "c8s/secrets-fetch/v1\x00"

// transcriptInput is the canonical form folded into the attestation
// REPORTDATA alongside the challenge: everything the release decision is made
// on, so a tampered claim, response key, or requested path fails evidence
// verification. List order is significant — both sides marshal the same value.
type transcriptInput struct {
	InitContainerDigests []string        `json:"init_container_digests"`
	ContainerDigests     []string        `json:"container_digests"`
	ResponsePubkey       string          `json:"response_pubkey"`
	Requests             []SecretRequest `json:"requests"`
}

// ReportDataForFetch computes the expected attestation REPORTDATA for a fetch
// request, mirroring ratls.ReportDataForKeyAndClaims: a domain-separated,
// length-framed SHA-384 transcript so no two distinct (challenge, request)
// pairs share a preimage:
//
//	SHA-384(domainSep || framed(challenge) || framed(canonical(request)))
//	  where framed(x) = uint64-BE(len(x)) || x
//	  canonical(request) = json.Marshal of the request sans evidence
func ReportDataForFetch(challenge []byte, req FetchRequest) ([64]byte, error) {
	canonical, err := json.Marshal(transcriptInput{
		InitContainerDigests: req.InitContainerDigests,
		ContainerDigests:     req.ContainerDigests,
		ResponsePubkey:       req.ResponsePubkey,
		Requests:             req.Requests,
	})
	if err != nil {
		return [64]byte{}, err
	}

	var out [64]byte
	h := sha512.New384()
	h.Write([]byte(fetchDomainSep))
	for _, field := range [][]byte{challenge, canonical} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// VerifyReportData wraps the fetch transcript into the attestation-api verify
// request, the same shape /attest uses.
func VerifyReportData(evidence types.AttestationEvidence, reportData [64]byte) types.VerifyRequest {
	rd := types.NewBase64Bytes(reportData[:sha512.Size384])
	return types.VerifyReportData(evidence, rd)
}
