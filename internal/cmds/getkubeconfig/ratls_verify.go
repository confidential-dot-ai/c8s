package getkubeconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// newRATLSClient builds an HTTP client whose :8443 dial is verified with the
// operator's OWN in-process verifier (attestation-go), with no trust in the
// guest's attestation-api and not TOFU. The cred-release serving cert embeds a
// fresh TDX quote bound to the cert's public key (ratls.ReportDataForKey);
// verifyServerCert extracts it, asserts the quote covers this exact cert key,
// and enforces the same full measured-identity policy as the attest gate. A
// host MITM can't forge that quote, so a successful handshake proves the
// channel terminates inside the measured, operator-key-bound guest.
//
// Go's own chain/hostname verification is disabled (InsecureSkipVerify): the
// serving cert is self-signed and carries no SAN for the per-launch IP. RA-TLS
// replaces it — the quote binding is strictly stronger than a CA chain here.
func newRATLSClient(cfg Config, exp measuredPolicy) *http.Client {
	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // RA-TLS in VerifyConnection is the real check
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("ratls: server presented no certificate")
					}
					return verifyServerCert(cs.PeerCertificates[0], exp)
				},
			},
		},
	}
}

// verifyServerCert runs the RA-TLS check on the :8443 leaf cert: it
// authenticates the certificate body itself (validity within the shared skew
// bound; the self-signature under the cert's own key — the quote binds only
// the key, so without that check any other body field could be rewritten),
// then pulls the embedded TDX quote, binds it to the cert's own public key,
// verifies it in-process with attestation-go (HW chain + report_data
// binding), and enforces the full measured-identity policy — identical to the
// attest gate. Fails closed on any missing piece.
func verifyServerCert(leaf *x509.Certificate, exp measuredPolicy) error {
	// This leaf is self-signed by construction (newRATLSClient's doc comment:
	// there is no CA on this path at all), so the classification must come
	// back BodySelfSigned. Assert it rather than discard it: a CA-vouched
	// result here means the presented cert was issued by something, and
	// nothing in this flow would check that issuer — the body would ride in
	// unauthenticated under a genuine quote.
	body, err := certutil.AuthenticateLeafBody(leaf, time.Now())
	if err != nil {
		return fmt.Errorf("ratls: %w", err)
	}
	if body != certutil.BodySelfSigned {
		return fmt.Errorf("ratls: cred-release serving cert is not self-signed (issuer != subject), so its body is authenticated by nothing this flow checks; the RA-TLS leaf must carry its own signature under the attested key")
	}
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
	// the attested guest to THIS TLS channel. The 64-byte ReportDataForKey
	// output (48-byte hash + zero tail) matches the quote's report_data field
	// exactly.
	rd, err := ratls.ReportDataForKey(leaf.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("ratls: compute expected report_data: %w", err)
	}

	envJSON, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("ratls: marshal embedded evidence: %w", err)
	}

	// Reuse the exact verifier the attest gate uses — one funnel, one policy.
	if _, err := verifyEvidence(envJSON, rd[:], exp); err != nil {
		return fmt.Errorf("ratls: %w", err)
	}
	return nil
}
