package allowlistclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Client is an HTTP client for the CDS allowlist API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new allowlist client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// NewClientWithHTTP creates a new allowlist client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// List returns all allowlisted image digests.
func (c Client) List(ctx context.Context) (types.AllowlistListResponse, error) {
	url := c.baseURL + "/allowlist"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return types.AllowlistListResponse{}, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return types.AllowlistListResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return types.AllowlistListResponse{}, &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}

	body, err := readCapped(resp.Body, maxAllowlistResponseBytes)
	if err != nil {
		return types.AllowlistListResponse{}, err
	}
	var result types.AllowlistListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return types.AllowlistListResponse{}, err
	}
	return result, nil
}

// Authorizer produces the HTTP Authorization header value for a mutation,
// binding it to the exact method, URL path, and body the client will send.
// Implemented by operatorauth.Signer.
type Authorizer interface {
	Authorization(method, path string, body []byte) (string, error)
}

// Add adds an image digest to the allowlist. The write is authorized by auth
// (an operator credential); auth is invoked with the exact request body so the
// resulting token binds to it.
func (c Client) Add(ctx context.Context, digest types.Digest, image string, auth Authorizer) error {
	data, err := json.Marshal(types.AllowlistAddRequest{Digest: digest, Image: image})
	if err != nil {
		return err
	}
	return c.mutate(ctx, http.MethodPost, data, auth)
}

// Delete removes image digests from the allowlist. Returns an error with 404
// status if any digest does not exist.
func (c Client) Delete(ctx context.Context, digests []types.Digest, auth Authorizer) error {
	data, err := json.Marshal(types.AllowlistDeleteRequest{Digests: digests})
	if err != nil {
		return err
	}
	return c.mutate(ctx, http.MethodDelete, data, auth)
}

// Replace atomically swaps the entire allowlist for digests. CDS assigns the
// new version, so the caller passes no version.
func (c Client) Replace(ctx context.Context, digests map[types.Digest]string, auth Authorizer) error {
	data, err := json.Marshal(types.AllowlistReplaceRequest{Digests: digests})
	if err != nil {
		return err
	}
	return c.mutate(ctx, http.MethodPut, data, auth)
}

// mutate sends a body-bound, authorized write to /allowlist. auth is called
// with the exact method, path, and bytes sent, guaranteeing the token's
// bindings match what the server receives.
func (c Client) mutate(ctx context.Context, method string, body []byte, auth Authorizer) error {
	if auth == nil {
		return fmt.Errorf("allowlistclient: nil Authorizer")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/allowlist", bytes.NewReader(body))
	if err != nil {
		return err
	}
	authz, err := auth.Authorization(method, req.URL.Path, body)
	if err != nil {
		return fmt.Errorf("authorize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authz)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// maxAllowlistResponseBytes caps CDS response bodies. Generous for a
// realistic fleet (a sha256 entry + image ref is ~150 bytes; 4 MiB ≈ 27k
// entries) but bounded so a compromised or buggy CDS can't OOM the
// plugin process on every worker node.
const maxAllowlistResponseBytes = 4 * 1024 * 1024

// errAllowlistResponseTooLarge is returned when CDS exceeds the body cap.
var errAllowlistResponseTooLarge = fmt.Errorf("allowlist response exceeds %d bytes", maxAllowlistResponseBytes)

// FetchAllowlistConditional issues GET /allowlist with If-None-Match.
// notModified is true on a 304 (allowlist nil, etag ""); on 200 the
// parsed allowlist is returned with the new ETag (which may be empty).
func (c Client) FetchAllowlistConditional(ctx context.Context, ifNoneMatch string) (*allowlist.Allowlist, string, bool, error) {
	url := c.baseURL + "/allowlist"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("create request: %w", err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch allowlist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		io.Copy(io.Discard, resp.Body)
		return nil, "", true, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := readCapped(resp.Body, maxAllowlistResponseBytes)
		return nil, "", false, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	if ct := resp.Header.Get("Content-Type"); !isJSONContentType(ct) {
		return nil, "", false, fmt.Errorf("fetch allowlist: unexpected content type: %s", ct)
	}

	body, err := readCapped(resp.Body, maxAllowlistResponseBytes)
	if err != nil {
		return nil, "", false, err
	}

	wl, err := allowlist.ParseJSON(body)
	if err != nil {
		return nil, "", false, err
	}
	return wl, resp.Header.Get("ETag"), false, nil
}

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

// readCapped reads up to maxBytes from r and returns errAllowlistResponseTooLarge
// if the source produced more.
func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, errAllowlistResponseTooLarge
	}
	return body, nil
}

// StatusError represents a non-success HTTP response.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("server returned %d", e.Status)
}
