package getkubeconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// newRATLSClient builds an HTTP client whose :8443 dial is verified with the
// operator's OWN local attestation-cli — no trust in the guest's attestation-api,
// not TOFU. The cred-release serving cert embeds a fresh TDX quote bound to the
// cert's public key (ratls.ReportDataForKey); verifyServerCert extracts it,
// asserts the quote covers this exact cert key, and asserts rtmr_3 == H(op_pub).
// A host MITM can't forge that quote, so a successful handshake proves the
// channel terminates inside the measured, operator-key-bound guest.
//
// Go's own chain/hostname verification is disabled (InsecureSkipVerify): the
// serving cert is self-signed and carries no SAN for the per-launch IP. RA-TLS
// replaces it — the quote binding is strictly stronger than a CA chain here.
func newRATLSClient(cfg Config, operatorPubPEM []byte) *http.Client {
	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // RA-TLS in VerifyConnection is the real check
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("ratls: server presented no certificate")
					}
					return verifyServerCert(cs.PeerCertificates[0], operatorPubPEM)
				},
			},
		},
	}
}

// verifyServerCert runs the RA-TLS check on the :8443 leaf cert: it pulls the
// embedded TDX quote, binds it to the cert's own public key, verifies it with
// the local attestation-cli (HW chain + report_data freshness), and asserts
// rtmr_3 equals expectedRTMR3(op_pub). Fails closed on any missing piece.
func verifyServerCert(leaf *x509.Certificate, operatorPubPEM []byte) error {
	att, err := ratls.ExtractAttestation(leaf)
	if err != nil {
		return fmt.Errorf("ratls: %w", err)
	}
	evidence, ok := att.EmbeddedEvidence()
	if !ok {
		// TDX always carries a JSON envelope in the RA-TLS extension; its
		// absence means the cert isn't a genuine TDX RA-TLS cert.
		return fmt.Errorf("ratls: server cert carries no TDX attestation envelope")
	}

	// The quote's report_data must be SHA-384(cert pubkey) — this is what ties
	// the attested guest to THIS TLS channel. attestation-cli zero-pads the
	// expected value to the quote's 64-byte report_data, so the 64-byte
	// ReportDataForKey output (48-byte hash + zero tail) matches exactly.
	rd, err := ratls.ReportDataForKey(leaf.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("ratls: compute expected report_data: %w", err)
	}

	envJSON, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("ratls: marshal embedded evidence: %w", err)
	}

	// Reuse the same local verifier the RTMR[3] gate uses. No context here (the
	// TLS callback has none); Background is fine — the client Timeout still
	// bounds the surrounding request.
	claims, err := runAttestationCLIVerify(context.Background(), envJSON, hex.EncodeToString(rd[:]))
	if err != nil {
		return fmt.Errorf("ratls: attestation-cli verify: %w", err)
	}

	sigValid, _ := claims["signature_valid"].(bool)
	rdMatch, _ := claims["report_data_match"].(bool)
	if !sigValid {
		return fmt.Errorf("ratls: server quote signature invalid")
	}
	if !rdMatch {
		return fmt.Errorf("ratls: server quote report_data not bound to the presented cert key (MITM)")
	}

	got := platformDataString(claims, "rtmr_3")
	want := expectedRTMR3(operatorPubPEM)
	if got == "" {
		return fmt.Errorf("ratls: server quote carries no rtmr_3")
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("ratls: server RTMR[3] mismatch: node reports %s, operator key implies %s", got, want)
	}
	return nil
}
