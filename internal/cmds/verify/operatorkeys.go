package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// maxOperatorKeysBytes caps the /operator-keys response. A pinned key bundle is
// a handful of PEM blocks (~200 bytes each); 256 KiB is far beyond any real
// bundle but bounds a misbehaving endpoint.
const maxOperatorKeysBytes = 256 * 1024

// fetchOperatorKeyFingerprints GETs <base>/operator-keys and returns a hex
// SHA-256 fingerprint of each pinned operator public key (of its PKIX/SPKI DER,
// so `openssl pkey -pubin -outform DER < operator.pub | sha256sum` reproduces
// it).
//
// The fetch is bound to the endpoint whose attestation was just verified: the
// TLS handshake requires the presented leaf certificate's SHA-256 to equal
// wantCertSHA256 (the attested serving cert), so a different endpoint — or a
// MITM on this second connection — cannot inject its own key list into the
// report. It does NOT make the keys attested: they remain CDS-reported config
// outside the launch measurement.
//
// A 404 returns ("", nil, nil): the endpoint reports allowlist writes disabled
// (or predates /operator-keys); note distinguishes that from an error.
func fetchOperatorKeyFingerprints(ctx context.Context, base, serverName, wantCertSHA256 string, timeout time.Duration) (fingerprints []string, note string, err error) {
	if wantCertSHA256 == "" {
		return nil, "", fmt.Errorf("no attested serving certificate to bind the fetch to")
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // trust comes from the attested-cert pin below, not PKI
		ServerName:         serverName,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if got := hex.EncodeToString(sum[:]); got != wantCertSHA256 {
				return fmt.Errorf("serving cert changed between attestation and key fetch (got sha256 %s, attested %s)", got, wantCertSHA256)
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/operator-keys", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch /operator-keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "endpoint reports no pinned operator keys (allowlist writes disabled)", nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("/operator-keys returned %d", resp.StatusCode)
	}

	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxOperatorKeysBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read /operator-keys: %w", err)
	}
	if len(pemBytes) > maxOperatorKeysBytes {
		return nil, "", fmt.Errorf("/operator-keys response exceeds %d bytes", maxOperatorKeysBytes)
	}

	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse /operator-keys: %w", err)
	}
	for _, pub := range keys {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, "", fmt.Errorf("fingerprint operator key: %w", err)
		}
		sum := sha256.Sum256(der)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	return fingerprints, "", nil
}
