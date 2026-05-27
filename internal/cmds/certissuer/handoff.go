package certissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/internal/issuer"
)

type HandoffRequest = issuer.HandoffRequest
type HandoffResponse = issuer.HandoffResponse

// newHandoffHandler wires *Issuer + public bundle into issuer.HandoffDeps and
// returns the package-level handler. Snapshot is the only callback; the rest
// is field plumbing.
func newHandoffHandler(iss *Issuer, bm *issuer.BundleManager, signer *ecdsa.PrivateKey, src issuer.HandoffEARSource) (*issuer.HandoffHandler, error) {
	return issuer.NewHandoffHandler(issuer.HandoffDeps{
		Logger:              iss.Logger,
		KeyProvider:         iss.keyProvider,
		ExpectedIssuer:      iss.ExpectedIssuer,
		AllowedMeasurements: iss.HandoffMeasurements,
		Bundle:              bm,
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			b := iss.getBundle()
			if b == nil {
				return nil, nil, nil, false
			}
			return b.caCert, b.caKey, b.parentCert, true
		},
	}, signer, src)
}

// requestHandoff is the cert-issuer-side client wrapper around
// issuer.RequestHandoff, sourcing the EAR verification context from *Issuer.
func requestHandoff(ctx context.Context, peerURL, requesterEAR string, signer *ecdsa.PrivateKey, iss *Issuer, client *http.Client) (*issuer.HandoffMaterial, error) {
	return issuer.RequestHandoff(ctx, issuer.HandoffClientDeps{
		KeyProvider:         iss.keyProvider,
		ExpectedIssuer:      iss.ExpectedIssuer,
		AllowedMeasurements: iss.HandoffMeasurements,
	}, peerURL, requesterEAR, signer, client)
}

type staticHandoffEARSource struct {
	ear string
}

func (s staticHandoffEARSource) Current() (string, error) {
	return strings.TrimSpace(s.ear), nil
}
