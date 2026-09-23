package policystate

// Response and request bodies of the CDS endpoints. They live here rather than
// in the client so CDS and its clients share one definition, and they follow
// the same strict-decode rule as every other protocol object.

// Head is GET /.well-known/c8s/allowlist/latest: the publication head. It says
// what was published, not what any participant has applied.
type Head struct {
	Authority    string `json:"authority"`
	Version      uint64 `json:"version"`
	PolicyDigest string `json:"policy_digest"`
	LogHead      string `json:"log_head"`
}

// ChallengeRequest is the body of POST /.well-known/c8s/state/challenge.
type ChallengeRequest struct {
	Nonce string `json:"nonce"`
}

// Well-known route paths under the /.well-known/c8s prefix. Objects — policy
// documents and journal entries alike — are fetched by content digest from one
// path, so a mirror needs no knowledge of what it serves.
const (
	PathPrefix       = "/.well-known/c8s"
	PathObjectPrefix = PathPrefix + "/objects/sha256/"
	PathLatest       = PathPrefix + "/allowlist/latest"
	PathState        = PathPrefix + "/state"
	PathChallenge    = PathPrefix + "/state/challenge"
	PathEnroll       = PathPrefix + "/participants/enroll"
	PathAck          = PathPrefix + "/participants/ack"
	PathComplete     = PathPrefix + "/participants/complete"
)
