package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	pkgsecrets "github.com/confidential-dot-ai/c8s/pkg/secrets"
)

// brokerClient is a broker-identity-verified CDS client: values cross the
// wire wrapped to the broker encryption key, so a same-measurement fake CDS
// (which cannot hold the mesh CA key and therefore cannot mint this identity)
// never sees plaintext.
type brokerClient struct {
	hc      *http.Client
	baseURL string
	encPub  []byte
	signing *ecdsa.PublicKey
}

func newBrokerClient(hc *http.Client, baseURL string, roots *x509.CertPool, identityJSON []byte) (*brokerClient, error) {
	var bi pkgsecrets.BrokerIdentity
	dec := json.NewDecoder(bytes.NewReader(identityJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bi); err != nil {
		return nil, fmt.Errorf("decode broker identity: %w", err)
	}
	signing, encPub, err := bi.Verify(roots)
	if err != nil {
		return nil, err
	}
	return &brokerClient{hc: hc, baseURL: baseURL, encPub: encPub, signing: signing}, nil
}

// authorizer signs one request, mirroring allowlistclient.Authorizer.
type authorizer interface {
	Authorization(method, path string, body []byte) (string, error)
}

// put wraps value to the broker encryption key and deposits it at (entry, path).
func (c *brokerClient) put(ctx context.Context, entry, path string, value []byte, auth authorizer) error {
	wrapped, err := pkgsecrets.Wrap(c.encPub, value, pkgsecrets.DepositAAD(entry, path))
	if err != nil {
		return fmt.Errorf("wrap value: %w", err)
	}
	body, err := json.Marshal(wrapped)
	if err != nil {
		return err
	}
	return c.mutate(ctx, http.MethodPut, secretPath(entry, path), body, auth)
}

// get reads back (entry, path), unwrapping to a fresh ephemeral key.
func (c *brokerClient) get(ctx context.Context, entry, path string, auth authorizer) ([]byte, error) {
	priv, pub, err := pkgsecrets.GenerateX25519()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+secretPath(entry, path)+"?pubkey="+url.QueryEscape(base64.StdEncoding.EncodeToString(pub)), nil)
	if err != nil {
		return nil, err
	}
	authz, err := auth.Authorization(http.MethodGet, req.URL.Path, nil)
	if err != nil {
		return nil, fmt.Errorf("authorize request: %w", err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp)
	}
	var fetchResp pkgsecrets.FetchResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fetchResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if err := pkgsecrets.VerifyResponseSignature(c.signing, fetchResp.Payload, fetchResp.Signature); err != nil {
		return nil, err
	}
	value, err := pkgsecrets.Unwrap(priv, pkgsecrets.DepositAAD(entry, path), fetchResp.Payload)
	if err != nil {
		return nil, fmt.Errorf("unwrap response: %w", err)
	}
	return value, nil
}

// del removes (entry, path).
func (c *brokerClient) del(ctx context.Context, entry, path string, auth authorizer) error {
	return c.mutate(ctx, http.MethodDelete, secretPath(entry, path), nil, auth)
}

// secretPath builds the route path for a (entry, path) ref: the entry is one
// path segment; the secret path keeps its slashes under /paths/.
func secretPath(entry, p string) string {
	return "/secrets/entries/" + url.PathEscape(entry) + "/paths" + p
}

// mutate sends a body-bound, authorized write (mirrors allowlistclient).
func (c *brokerClient) mutate(ctx context.Context, method, path string, body []byte, auth authorizer) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	authz, err := auth.Authorization(method, req.URL.Path, body)
	if err != nil {
		return fmt.Errorf("authorize request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", authz)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusError(resp)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func statusError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}
