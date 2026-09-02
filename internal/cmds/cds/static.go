// Static (sealed) allowlist mode: --static-allowlist loads the seed document
// as the one immutable policy for this CDS's lifetime. Operator writes are
// disabled, and the mesh CA certificate is minted carrying the document's
// canonical SHA-256 (ratls.OIDStaticAllowlist) next to an RA-TLS attestation
// extension binding the CA public key — so a relying party that pins the
// digest can check, off the CA certificate alone, that this deployment's
// trust root was born in a measured CDS launched to enforce exactly that
// policy. Changing the policy means launching a new CDS, which mints a new
// CA, which every pinning client notices. See docs/static-allowlist.md.

package cds

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// staticCAEvidenceTimeout bounds the attestation-api call that produces the
// sealed CA's own evidence at startup.
const staticCAEvidenceTimeout = 30 * time.Second

// seedStoreStatic reads the JSON allowlist at path and REPLACES the store
// contents with it, unlike seedStore's additive merge: a sealed CDS must
// enforce exactly the seed document, so entries left over in a persistent
// store from an earlier, wider policy must not survive into the sealed set.
func seedStoreStatic(store *allowlist.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read allowlist seed %q: %w", path, err)
	}
	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}
	if err := store.ReplaceAll(seed); err != nil {
		return fmt.Errorf("replace allowlist store with seed: %w", err)
	}
	slog.Info("allowlist store replaced with the static seed",
		"floor", len(seed.Digests), "workloads", len(seed.Workloads))
	return nil
}

// staticCAExtensions returns the extension callback a sealed mesh CA is
// minted with: the RA-TLS attestation extension over the CA public key
// (nonce-free, the same binding every serving cert uses, so existing
// verifiers re-check it unchanged) and the static-allowlist stamp carrying
// allowlistDigest. Any failure aborts CA creation — a sealed CDS must not
// come up with an unattested or unstamped root.
func staticCAExtensions(ctx context.Context, attestationApiURL string, allowlistDigest []byte) func(pub crypto.PublicKey) ([]pkix.Extension, error) {
	return func(pub crypto.PublicKey) ([]pkix.Extension, error) {
		evCtx, cancel := context.WithTimeout(ctx, staticCAEvidenceTimeout)
		defer cancel()
		attExt, err := attestclient.NewClient("").AttestationExtension(evCtx, attestationApiURL, pub)
		if err != nil {
			return nil, fmt.Errorf("attest the mesh CA key: %w", err)
		}
		stampExt, err := ratls.MarshalStaticAllowlistExtension(&ratls.StaticAllowlist{AllowlistDigest: allowlistDigest})
		if err != nil {
			return nil, err
		}
		return []pkix.Extension{attExt, stampExt}, nil
	}
}
