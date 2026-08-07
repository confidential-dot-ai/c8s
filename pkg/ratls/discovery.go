package ratls

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// AttestedCertFromDiscovery validates the attestation carrier fields of a
// tls-lb discovery document and returns the attested CDS serving certificate
// together with the expected REPORTDATA: SHA-384(cert pubkey ‖ challenge),
// get-cert's issuance binding (ReportDataForKey).
//
// Policy stays with the caller — public_tls.mode checks, platform defaulting,
// and actually verifying the evidence — because the two consumers legitimately
// differ: lbdiscovery binds a live connection to the attested cert (and must
// refuse webpki mode), while `c8s verify` gathers evidence for offline
// verification and never binds a connection.
func AttestedCertFromDiscovery(d *types.DiscoveryDocument) (*x509.Certificate, [64]byte, error) {
	if len(d.Attestation.Evidence) == 0 {
		return nil, [64]byte{}, fmt.Errorf("discovery document carries no attestation.evidence")
	}
	block, _ := pem.Decode([]byte(d.CDSTLS.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, [64]byte{}, fmt.Errorf("discovery cds_tls.certificate_pem is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, [64]byte{}, fmt.Errorf("parse cds cert: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(d.Attestation.Challenge)
	if err != nil {
		return nil, [64]byte{}, fmt.Errorf("decode challenge: %w", err)
	}
	rd, err := ReportDataForKey(cert.PublicKey, challenge)
	if err != nil {
		return nil, [64]byte{}, fmt.Errorf("compute expected REPORTDATA: %w", err)
	}
	return cert, rd, nil
}
