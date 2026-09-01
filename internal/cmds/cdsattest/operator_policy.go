package cdsattest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const maxOperatorPolicyBytes = 256 << 10

// OperatorPolicy is the operator key set that the active CDS uses for writes.
// It is public policy data. It contains no private key.
type OperatorPolicy struct {
	KeysPEM string
	SHA256  string
}

// OperatorPolicyProvider reads the current operator policy from the live CDS.
// The production client uses pinned RA-TLS and presents the tls-lb mesh leaf.
// This makes an offline same-image CDS fail the client-certificate handshake.
type OperatorPolicyProvider interface {
	Active(ctx context.Context) (OperatorPolicy, error)
}

type liveOperatorPolicyProvider struct {
	baseURL string
	client  *http.Client
}

func newLiveOperatorPolicyProvider(baseURL string, client *http.Client) (OperatorPolicyProvider, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("operator policy requires a CDS URL")
	}
	if client == nil {
		return nil, fmt.Errorf("operator policy requires an RA-TLS client")
	}
	return &liveOperatorPolicyProvider{baseURL: baseURL, client: client}, nil
}

func (p *liveOperatorPolicyProvider) Active(ctx context.Context) (OperatorPolicy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/operator-keys", nil)
	if err != nil {
		return OperatorPolicy{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return OperatorPolicy{}, fmt.Errorf("get active operator keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return OperatorPolicy{}, fmt.Errorf("get active operator keys: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxOperatorPolicyBytes + 1}
	pemBytes, err := io.ReadAll(limited)
	if err != nil {
		return OperatorPolicy{}, fmt.Errorf("read active operator keys: %w", err)
	}
	if len(pemBytes) > maxOperatorPolicyBytes {
		return OperatorPolicy{}, fmt.Errorf("active operator keys exceed %d bytes", maxOperatorPolicyBytes)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return OperatorPolicy{}, fmt.Errorf("parse active operator keys: %w", err)
	}
	hash, err := operatorauth.KeySetHash(keys)
	if err != nil {
		return OperatorPolicy{}, fmt.Errorf("hash active operator keys: %w", err)
	}
	return OperatorPolicy{KeysPEM: string(pemBytes), SHA256: hash}, nil
}
