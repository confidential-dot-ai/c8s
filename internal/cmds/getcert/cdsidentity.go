// Republishing CDS's own RA-TLS certificate: the trust root a third party
// attests once and caches. See docs/ratls.md and types.CDSIdentityDiscovery for
// why this is distinct from the certificate CDS issues to this workload.

package getcert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// cdsIdentityRecorder captures the CDS certificate this process verified while
// obtaining its own certificate, so it can be republished in the discovery
// document.
//
// Republishing is only meaningful because it records a certificate that already
// passed RA-TLS verification here (ratls.ClientConfig.OnVerifiedPeer fires only
// after that succeeds). It is also safe to republish over an untrusted path:
// the certificate is self-authenticating, carrying hardware evidence over its
// own public key and claims, so a tampered or forged copy fails the client's
// verification. What republishing does NOT prevent is substituting an OLDER
// genuine certificate: nothing in the certificate is bound to a client
// challenge, so a replayed one verifies until its validity window closes.
// Clients get bounded staleness — the window plus any newest-seen floor they
// keep — not replay immunity.
type cdsIdentityRecorder struct {
	mu         sync.Mutex
	cert       *x509.Certificate
	observedAt time.Time
}

// observe records the verified CDS certificate. Safe to call on every
// handshake; the latest wins, which is what we want when CDS re-issues (it
// does so whenever the live allowlist changes).
func (r *cdsIdentityRecorder) observe(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cert = cert
	r.observedAt = time.Now().UTC()
}

// discovery renders the recorded certificate, or nil when none has been
// observed yet. Nil is correct rather than an error: the field is omitempty, so
// a consumer sees its absence and falls back to reaching CDS directly instead
// of trusting a half-populated record.
func (r *cdsIdentityRecorder) discovery() *types.CDSIdentityDiscovery {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert == nil {
		return nil
	}
	sum := sha256.Sum256(r.cert.Raw)
	return &types.CDSIdentityDiscovery{
		CertificatePEM:    string(certutil.EncodeCertPEM(r.cert.Raw)),
		CertificateSHA256: hex.EncodeToString(sum[:]),
		ObservedAt:        r.observedAt.Format(time.RFC3339),
	}
}
