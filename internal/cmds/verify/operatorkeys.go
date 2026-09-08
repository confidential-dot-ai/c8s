package verify

import (
	"context"
	"crypto/sha256"
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
// it), plus the served set's KeySetDigest for comparison against the attested
// --operator-keys bundle (applySandboxPolicy).
//
// A 404 sets note and returns the empty-set digest: the endpoint reports
// allowlist writes disabled, which --operator-keys can still be checked against.
func fetchOperatorKeyFingerprints(ctx context.Context, base, serverName, wantCertSHA256 string, timeout time.Duration) (fingerprints []string, digest []byte, note string, err error) {
	resp, err := fetchAttested(ctx, base+"/operator-keys", serverName, wantCertSHA256, timeout)
	if err != nil {
		return nil, nil, "", fmt.Errorf("fetch /operator-keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Writes disabled — the empty set. Returning its digest lets
		// --operator-keys distinguish "no keys" from "not fetched".
		emptyDigest, err := operatorauth.KeySetDigest(nil)
		if err != nil {
			return nil, nil, "", err
		}
		return nil, emptyDigest, "endpoint reports no pinned operator keys (allowlist writes disabled)", nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, "", fmt.Errorf("/operator-keys returned %d", resp.StatusCode)
	}

	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxOperatorKeysBytes+1))
	if err != nil {
		return nil, nil, "", fmt.Errorf("read /operator-keys: %w", err)
	}
	if len(pemBytes) > maxOperatorKeysBytes {
		return nil, nil, "", fmt.Errorf("/operator-keys response exceeds %d bytes", maxOperatorKeysBytes)
	}

	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse /operator-keys: %w", err)
	}
	for _, pub := range keys {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, nil, "", fmt.Errorf("fingerprint operator key: %w", err)
		}
		sum := sha256.Sum256(der)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	if digest, err = operatorauth.KeySetDigest(keys); err != nil {
		return nil, nil, "", err
	}
	return fingerprints, digest, "", nil
}
