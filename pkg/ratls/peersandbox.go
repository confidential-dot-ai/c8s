package ratls

import (
	"crypto/tls"
)

// PeerSandboxID returns the CRI pod sandbox ID a verified TLS peer presented,
// or "" when its leaf carries no sandbox-ID extension. For an HTTP server the
// connection state is on the request: PeerSandboxID(r.TLS).
//
// Read-only: CDS stamps the ID into the signed leaf only after verifying the
// inventory-signed sandbox token, so this reads the leaf, it does not
// re-verify.
//
// INVARIANT: only call on a connection an RA-TLS verify callback accepted (the
// tls.Config from NewServerTLSConfig / NewClientTLSConfig). Acceptance is what
// authenticates the ID — the trust model, and its honest-inventory ceiling, are
// in docs/ratls.md, "Sandbox identity".
func PeerSandboxID(cs *tls.ConnectionState) (string, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return "", nil
	}
	return SandboxIDFromCert(cs.PeerCertificates[0])
}
