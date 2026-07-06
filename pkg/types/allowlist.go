package types

// AllowlistListResponse is the response body for GET /allowlist.
type AllowlistListResponse struct {
	Version string            `json:"version"`
	Digests map[Digest]string `json:"digests"`
}

// AllowlistAddRequest is the request body for POST /allowlist.
type AllowlistAddRequest struct {
	Digest Digest `json:"digest"`
	Image  string `json:"image"`
}

// AllowlistDeleteRequest is the request body for DELETE /allowlist.
type AllowlistDeleteRequest struct {
	Digests []Digest `json:"digests"`
}

// AllowlistReplaceRequest is the request body for PUT /allowlist: the complete
// desired digest set. It carries no version — CDS owns the version and bumps it
// on every replace, so an operator never has to read-modify-write it.
type AllowlistReplaceRequest struct {
	Digests map[Digest]string `json:"digests"`
}
