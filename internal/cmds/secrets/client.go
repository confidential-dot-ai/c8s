package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
)

// client writes secrets to CDS over an attested channel.
type client struct {
	baseURL string
	http    *http.Client
}

// authorizer mints the operator Authorization header for one write, bound to
// its method, path, and body. Implemented by operatorauth.Signer.
type authorizer interface {
	Authorization(method, path string, body []byte) (string, error)
}

// result is what a write did. Created reports a path that held nothing;
// Existing names what put the value the write displaced, or on a refusal what
// is still there.
type result struct {
	Created  bool
	Existing intsecrets.Origin
	// Refused reports that the path already held a value and the write did not
	// carry overwrite intent, so nothing changed.
	Refused bool
}

// put sends one value. overwrite travels in the body rather than the URL so the
// operator token's body binding covers it.
func (c client) put(ctx context.Context, path string, value []byte, overwrite bool, auth authorizer) (result, error) {
	body, err := json.Marshal(intsecrets.PutRequest{
		Value:     base64.StdEncoding.EncodeToString(value),
		Overwrite: overwrite,
	})
	if err != nil {
		return result{}, err
	}

	url := c.baseURL + "/secrets" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return result{}, err
	}
	authz, err := auth.Authorization(http.MethodPut, req.URL.Path, body)
	if err != nil {
		return result{}, fmt.Errorf("authorize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authz)

	resp, err := c.http.Do(req)
	if err != nil {
		return result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return result{}, fmt.Errorf("read response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusCreated,
		resp.StatusCode == http.StatusConflict,
		resp.StatusCode == http.StatusOK && overwrite:
		var pr intsecrets.PutResponse
		if err := json.Unmarshal(raw, &pr); err != nil {
			return result{}, fmt.Errorf("decode response: %w", err)
		}
		return result{
			Created:  pr.Created,
			Existing: pr.Existing,
			Refused:  resp.StatusCode == http.StatusConflict,
		}, nil
	case resp.StatusCode == http.StatusOK:
		// 200 answers a replacement. Reading it as anything else would let the
		// CLI report a refusal for a write that landed.
		return result{}, fmt.Errorf("cds replaced a value for a request that did not ask to: %s", path)
	default:
		// A 404/405 with a non-JSON body never reached CDS: it is a front
		// door (an older tls-lb) without the /secrets route.
		if (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) && !json.Valid(raw) {
			return result{}, fmt.Errorf("%s answered %d without reaching CDS: this front door does not route /secrets. Upgrade tls-lb to a chart that publishes it (tlsLb.secrets.enabled), or use a direct CDS URL via a port-forward (kubectl port-forward svc/c8s-cds 8443:8443, then --url https://localhost:8443)", c.baseURL, resp.StatusCode)
		}
		return result{}, fmt.Errorf("cds returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
}

// explain asks CDS what a sandbox resolves to and why.
func (c client) explain(ctx context.Context, sandboxID string, auth authorizer) (intsecrets.ExplainResponse, error) {
	var out intsecrets.ExplainResponse
	url := c.baseURL + "/secrets-explain/" + sandboxID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return out, err
	}
	authz, err := auth.Authorization(http.MethodGet, req.URL.Path, nil)
	if err != nil {
		return out, fmt.Errorf("authorize request: %w", err)
	}
	req.Header.Set("Authorization", authz)

	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return out, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("cds returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// maxResponseBytes bounds a CDS reply. The largest is an explain report over
// every workload entry; anything approaching this is a wrong endpoint.
const maxResponseBytes = 1 << 20
