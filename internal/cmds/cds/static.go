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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/initdata"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
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

// parseSealedDigest decodes an expected canonical allowlist digest.
func parseSealedDigest(hexDigest string) ([]byte, error) {
	b, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%d bytes, want 32 (SHA-256 of the canonical allowlist)", len(b))
	}
	return b, nil
}

// checkExpectedSealedDigest refuses a seed that is not the document the
// operator installed with. On node-as-CVM the seed comes from the measured
// root, so a mismatch means the node image baked a different policy than the
// one being deployed against — the install must fail, not proceed sealing the
// wrong thing.
func checkExpectedSealedDigest(expectedHex string, got []byte) error {
	if expectedHex == "" {
		return nil
	}
	want, err := parseSealedDigest(expectedHex)
	if err != nil {
		return fmt.Errorf("--static-allowlist-digest: %w", err)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("static allowlist: the seed's canonical digest %x is not the expected %x — the baked (or seeded) document is not the one this install was given; rebuild the node image with that document or install with the document the node carries", got, want)
	}
	return nil
}

// checkInitDataSeal proves, from CDS's own hardware report, that the guest
// was launched committed to this policy: the kata shim hashed the init-data
// document into HOST_DATA / MRCONFIGID at launch, so a document whose digest
// matches the verified claim is launch-committed, and its
// c8s.cds.allowlist-seed-sha256 must be the sealed digest. Any gap fails
// closed — an unsealed launch of the same guest image must not present as
// sealed.
func checkInitDataSeal(ctx context.Context, attestationApiURL string, sealed []byte) error {
	raw, err := os.ReadFile(initdata.GuestDocumentPath)
	if err != nil {
		return fmt.Errorf("static allowlist: read launch-committed init-data %s: %w", initdata.GuestDocumentPath, err)
	}
	claim, err := verifiedOwnInitData(ctx, attestationApiURL)
	if err != nil {
		return err
	}
	want := initdata.Digest(raw)
	if subtle.ConstantTimeCompare(claim, want[:]) != 1 {
		return fmt.Errorf("static allowlist: init-data digest %x is not the launch-committed claim %x", want, claim)
	}
	doc, err := initdata.Parse(raw)
	if err != nil {
		return fmt.Errorf("static allowlist: parse init-data: %w", err)
	}
	if doc.Data[initdata.KeyRole] != initdata.RoleCDS {
		return fmt.Errorf("static allowlist: init-data role is %q, want %q", doc.Data[initdata.KeyRole], initdata.RoleCDS)
	}
	if got := doc.Data[initdata.KeyCDSAllowlistSeedSHA256]; got != hex.EncodeToString(sealed) {
		return fmt.Errorf("static allowlist: launch-committed %s is %q, but the sealed digest is %x", initdata.KeyCDSAllowlistSeedSHA256, got, sealed)
	}
	return nil
}

// verifiedOwnInitData asks the local attestation-api for a report over a fresh
// nonce and returns the init-data claim (HOST_DATA on SNP, the zero-padded
// MRCONFIGID on TDX) from the verified result.
func verifiedOwnInitData(ctx context.Context, attestationApiURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, staticCAEvidenceTimeout)
	defer cancel()
	nonce := make([]byte, sha512.Size384)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("static allowlist: nonce: %w", err)
	}
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, attestationApiURL, nonce)
	if err != nil {
		return nil, fmt.Errorf("static allowlist: own evidence: %w", err)
	}
	var expected [64]byte
	copy(expected[:], nonce)
	verdict, err := attestationclient.NewClient(attestationApiURL).VerifyEvidence(ctx, types.AttestationEvidence(resp), attestationclient.EvidencePolicy{ExpectedReportData: expected})
	if err != nil {
		return nil, fmt.Errorf("static allowlist: verify own evidence: %w", err)
	}
	claim, err := hex.DecodeString(verdict.Result.Claims.InitData)
	if err != nil {
		return nil, fmt.Errorf("static allowlist: init-data claim is not hex: %w", err)
	}
	switch len(claim) {
	case initdata.DigestSize:
		return claim, nil
	case 48: // TDX MRCONFIGID: sha256 zero-padded to 48 bytes
		for _, b := range claim[initdata.DigestSize:] {
			if b != 0 {
				return nil, fmt.Errorf("static allowlist: MRCONFIGID is not a zero-padded sha256")
			}
		}
		return claim[:initdata.DigestSize], nil
	default:
		return nil, fmt.Errorf("static allowlist: init-data claim is %d bytes, want %d", len(claim), initdata.DigestSize)
	}
}
