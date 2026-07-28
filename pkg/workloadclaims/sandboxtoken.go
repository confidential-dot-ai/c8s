// Signed sandbox tokens: the inventory's verifiable answer to "which pod sandbox
// is the calling process in". The inventory signs (sandbox ID, requester-key
// digest, CDS challenge nonce) with an in-process key it had CDS attest via
// POST /attest-key, so CDS can prove the sandbox ID came from a measured
// inventory, bound to one requester, and fresh for exactly the issuance whose
// challenge it carries (docs/ratls.md, "Sandbox identity"). Freshness rides
// the same single-use CDS challenge as the evidence — no clock.

package workloadclaims

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// maxNonceLen bounds the challenge a token may carry; the CDS challenge is a
// 32-byte nonce, so this rejects a hostile POST /sandbox body stuffing a large
// OCTET STRING into the signed token.
const maxNonceLen = 128

// sandboxTokenDomainSep tags the token signature preimage so an inventory-key
// signature over a token can never be confused with any other statement by
// the same key. Its "v1" names the statement type, not the token structure —
// sandboxTokenVersion versions that, inside the signed bytes.
var sandboxTokenDomainSep = []byte("c8s/sandbox-token/v1\x00")

// sandboxTokenVersion is 2: v1 carried no inventory address, so CDS had no
// attested way to reach the inventory back for the sandbox's digests. CDS and
// both inventories ship from the same chart, so there is no v1 read path.
const sandboxTokenVersion = 2

// sandboxTokenASN1 is the DER structure the inventory signs.
//
//	SandboxToken ::= SEQUENCE {
//	    version        INTEGER,
//	    sandboxId      IA5String,
//	    keyDigest      OCTET STRING (32),  -- SHA-256(requester PKIX pubkey DER)
//	    nonce          OCTET STRING,       -- the CDS challenge for this issuance
//	    inventoryAddr  IA5String           -- host:port of the digests endpoint
//	}
type sandboxTokenASN1 struct {
	Version       int
	SandboxID     string `asn1:"ia5"`
	KeyDigest     []byte
	Nonce         []byte
	InventoryAddr string `asn1:"ia5"`
}

// SignedSandboxToken is the inventory's SandboxPath answer.
type SignedSandboxToken struct {
	// Token is the DER-encoded sandbox token.
	Token []byte `json:"token"`
	// Signature is the inventory key's ASN.1 ECDSA-SHA256 signature over the
	// domain-separated Token bytes.
	Signature []byte `json:"signature"`
	// EAR is the CDS-issued EAR JWT (POST /attest-key) binding the inventory's
	// signing key to TEE evidence — how CDS resolves and trusts the key.
	EAR string `json:"ear"`
}

func sandboxTokenSigningHash(tokenDER []byte) []byte {
	h := sha256.New()
	h.Write(sandboxTokenDomainSep)
	h.Write(tokenDER)
	return h.Sum(nil)
}

// RequesterKeyDigest is the caller-key commitment a sandbox token carries:
// SHA-256 over the canonical PKIX DER of pub. Both sides derive it from a
// parsed key, so a non-canonical caller encoding cannot split the binding.
func RequesterKeyDigest(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal requester key: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

// VerifiedSandbox is what a valid token establishes: which sandbox the
// requester is in, and where to ask that sandbox's inventory what it is
// running.
type VerifiedSandbox struct {
	SandboxID string
	// InventoryAddr is the host:port of the signing inventory's digests
	// endpoint. It is inside the signature, so a hostile host cannot point CDS
	// at an endpoint of its choosing — and CDS re-verifies the RA-TLS identity
	// of whatever answers there anyway.
	InventoryAddr string
}

// Verify checks the envelope against the inventory key (which the caller must
// have resolved from the EAR and trusts), the requester key, and the CDS
// challenge for this request. It fails closed on a bad signature, a malformed
// or wrong-version token, a nonce that is not this request's challenge, or a
// requester-key mismatch. nonce is the single-use challenge CDS is consuming
// for the issuance, so a token cannot be replayed against a later request or
// pre-signed against a future one.
func (s *SignedSandboxToken) Verify(inventoryPub *ecdsa.PublicKey, requesterPub crypto.PublicKey, nonce []byte) (VerifiedSandbox, error) {
	if inventoryPub == nil {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: no inventory key to verify the sandbox token against")
	}
	if len(nonce) == 0 {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: no challenge to verify the sandbox token freshness against")
	}
	if !ecdsa.VerifyASN1(inventoryPub, sandboxTokenSigningHash(s.Token), s.Signature) {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: sandbox token signature invalid")
	}
	var tok sandboxTokenASN1
	rest, err := asn1.Unmarshal(s.Token, &tok)
	if err != nil {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: unmarshal sandbox token: %w", err)
	}
	if len(rest) > 0 {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: %d trailing bytes after sandbox token", len(rest))
	}
	if tok.Version != sandboxTokenVersion {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: unsupported sandbox token version %d", tok.Version)
	}
	if !bytes.Equal(tok.Nonce, nonce) {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: sandbox token nonce does not match this request's challenge")
	}
	want, err := RequesterKeyDigest(requesterPub)
	if err != nil {
		return VerifiedSandbox{}, err
	}
	if !bytes.Equal(tok.KeyDigest, want) {
		return VerifiedSandbox{}, fmt.Errorf("workloadclaims: sandbox token is bound to a different requester key")
	}
	if err := ValidateInventoryAddr(tok.InventoryAddr); err != nil {
		return VerifiedSandbox{}, err
	}
	return VerifiedSandbox{SandboxID: tok.SandboxID, InventoryAddr: tok.InventoryAddr}, nil
}

// EARSource obtains a CDS-issued EAR for the inventory's signing public key
// (PKIX DER) — attestclient.AttestKey over the inventory's RA-TLS CDS client.
type EARSource func(ctx context.Context, pubDER []byte) (string, error)

// earRefreshMargin re-obtains the inventory EAR this long before it expires, so
// a token never ships with an EAR that lapses mid-flight.
const earRefreshMargin = 2 * time.Minute

// SandboxTokenSigner signs sandbox tokens with an in-process P-256 key and
// caches the CDS-issued EAR credential for it, refreshing before expiry. The
// key never leaves the process; an inventory restart mints a new key and EAR.
type SandboxTokenSigner struct {
	key    *ecdsa.PrivateKey
	pubDER []byte
	source EARSource
	addr   string

	mu     sync.Mutex
	ear    string
	earExp time.Time
}

// NewSandboxTokenSigner generates the signing key. addr is the host:port of
// this inventory's digests endpoint, signed into every token so CDS can reach
// it back. No EAR is fetched yet — the first Sign obtains it, so inventory
// startup does not block on CDS.
func NewSandboxTokenSigner(source EARSource, addr string) (*SandboxTokenSigner, error) {
	if err := ValidateInventoryAddr(addr); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: generate sandbox signing key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal sandbox signing key: %w", err)
	}
	return &SandboxTokenSigner{key: key, pubDER: pubDER, source: source, addr: addr}, nil
}

// PublicKey is the signing key CDS sees in the inventory EAR.
func (s *SandboxTokenSigner) PublicKey() *ecdsa.PublicKey { return &s.key.PublicKey }

// Sign issues a signed sandbox token binding sandboxID to the requester-key
// digest and the CDS challenge nonce for this issuance.
func (s *SandboxTokenSigner) Sign(ctx context.Context, sandboxID string, requesterKeyDigest, nonce []byte) (*SignedSandboxToken, error) {
	if len(nonce) == 0 || len(nonce) > maxNonceLen {
		return nil, fmt.Errorf("workloadclaims: sandbox token nonce must be 1..%d bytes", maxNonceLen)
	}
	ear, err := s.credential(ctx)
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(sandboxTokenASN1{
		Version:       sandboxTokenVersion,
		SandboxID:     sandboxID,
		KeyDigest:     requesterKeyDigest,
		Nonce:         nonce,
		InventoryAddr: s.addr,
	})
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: marshal sandbox token: %w", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sandboxTokenSigningHash(der))
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: sign sandbox token: %w", err)
	}
	return &SignedSandboxToken{Token: der, Signature: sig, EAR: ear}, nil
}

// credential returns the cached EAR, re-obtaining it when it is missing or
// within earRefreshMargin of expiry. An EAR whose expiry cannot be read is
// still used but never cached.
func (s *SandboxTokenSigner) credential(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ear != "" && time.Now().Before(s.earExp.Add(-earRefreshMargin)) {
		return s.ear, nil
	}
	ear, err := s.source(ctx, s.pubDER)
	if err != nil {
		return "", fmt.Errorf("workloadclaims: obtain inventory EAR: %w", err)
	}
	exp, err := jwtExpiry(ear)
	if err != nil {
		exp = time.Time{}
	}
	s.ear, s.earExp = ear, exp
	return ear, nil
}

// jwtExpiry reads the exp claim without verifying the signature — the inventory
// only schedules its own refresh with it; CDS is the verifier.
func jwtExpiry(token string) (time.Time, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return time.Time{}, err
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}, fmt.Errorf("workloadclaims: EAR has no expiry")
	}
	return exp.Time, nil
}
