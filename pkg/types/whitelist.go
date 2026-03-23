package types

// WhitelistListResponse is the response body for GET /whitelist.
type WhitelistListResponse struct {
	Version string            `json:"version"`
	Digests map[Digest]string `json:"digests"`
}

// WhitelistAddRequest is the request body for POST /whitelist.
type WhitelistAddRequest struct {
	Digest Digest `json:"digest"`
	Image  string `json:"image"`
}

// WhitelistDeleteRequest is the request body for DELETE /whitelist.
type WhitelistDeleteRequest struct {
	Digests []Digest `json:"digests"`
}
