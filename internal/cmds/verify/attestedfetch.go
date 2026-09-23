package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// fetchAttested gets an HTTPS response bound to the previously attested leaf.
// The caller owns Body; closing it releases this fetch's connection.
func fetchAttested(ctx context.Context, endpoint, serverName, certSHA256 string, timeout time.Duration) (*http.Response, error) {
	if certSHA256 == "" {
		return nil, fmt.Errorf("no attested serving certificate to bind the fetch to")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("attested fetch requires HTTPS")
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   pinnedLeafTLS(serverName, certSHA256),
		},
	}
	return client.Do(req)
}

// pinnedLeafTLS is the client TLS config for a fetch that must land on the
// leaf the evidence attests: PKI is deliberately not verified — the
// fingerprint is what authenticates the peer. An empty certSHA256 pins
// nothing, for the callers whose integrity comes from the payload instead.
func pinnedLeafTLS(serverName, certSHA256 string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the attested leaf fingerprint authenticates the peer
		ServerName:         serverName,
	}
	if certSHA256 == "" {
		return cfg
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no peer certificate")
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if got := hex.EncodeToString(sum[:]); got != certSHA256 {
			return fmt.Errorf("serving cert changed between attestation and fetch (got sha256 %s, attested %s)", got, certSHA256)
		}
		return nil
	}
	return cfg
}
