package certissuer

import (
	"crypto/ecdsa"

	"github.com/lunal-dev/c8s/internal/issuer"
)

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
		Signer:              signer,
		EARSource:           src,
		Snapshot: func() (issuer.CASnapshot, bool) {
			b := iss.getBundle()
			if b == nil {
				return issuer.CASnapshot{}, false
			}
			return issuer.CASnapshot{Cert: b.caCert, Key: b.caKey, ParentCert: b.parentCert}, true
		},
	})
}
