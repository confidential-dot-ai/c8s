package localverify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewRATLSHTTPClient returns an http.Client whose TLS handshake verifies the
// peer's RA-TLS attestation extension against measurements (empty accepts any
// attested peer — callers warn). The in-process counterpart of
// ratls.NewVerifyingHTTPClient, with the same connection-pool and timeout
// knobs. verify is [Verify] in production, a stub in tests; verifyTimeout
// bounds each handshake's verification, KDS fetch included.
func NewRATLSHTTPClient(measurements [][]byte, verify VerifyFunc, verifyTimeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // attestation, not PKI, authenticates the peer — verified below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("localverify: no peer certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("localverify: parse peer cert: %w", err)
			}
			platform, evidence, erd, err := CertEnvelope(cert)
			if err != nil {
				return fmt.Errorf("localverify: peer attestation: %w", err)
			}
			// VerifyPeerCertificate carries no context; bound explicitly.
			ctx := context.Background()
			if verifyTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, verifyTimeout)
				defer cancel()
			}
			if _, err := verify(ctx, platform, evidence, Params{
				ExpectedReportData: erd,
				Measurements:       measurements,
			}); err != nil {
				return fmt.Errorf("localverify: peer attestation failed: %w", err)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          5,
			MaxConnsPerHost:       2,
			TLSClientConfig:       tlsCfg,
		},
	}
}
