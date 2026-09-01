// Package teewebpki owns the cluster TLS state for the tee-webpki front door.
// Private key seeds stay in CDS memory and move only through the attested CDS
// handoff. An admitted tls-lb replica can read the state over mesh mTLS.
package teewebpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"
)

const (
	Schema          = "c8s.tee-webpki/v1"
	SeedSize        = 32
	MaxCertificate  = 256 << 10
	MaxACMEState    = 256 << 10
	MaxRequestBytes = 512 << 10
)

// Snapshot is the protected cluster TLS state. TLSKeySeed and ACMEAccountSeed
// are secrets. CertificatePEM and ACMEState contain only public issuance data.
// CDS can copy the full value only through its encrypted handoff protocol.
type Snapshot struct {
	Schema          string          `json:"schema"`
	Version         uint64          `json:"version"`
	TLSKeySeed      []byte          `json:"tls_key_seed"`
	CertificatePEM  []byte          `json:"certificate_pem,omitempty"`
	CSRPEM          []byte          `json:"csr_pem,omitempty"`
	ACMEAccountSeed []byte          `json:"acme_account_seed"`
	ACMEState       json.RawMessage `json:"acme_state,omitempty"`
}

// PublicUpdate carries certificate and ACME renewal data into CDS. It cannot
// carry either private seed.
type PublicUpdate struct {
	Version        uint64          `json:"version"`
	CertificatePEM []byte          `json:"certificate_pem"`
	CSRPEM         []byte          `json:"csr_pem,omitempty"`
	ACMEState      json.RawMessage `json:"acme_state,omitempty"`
}

// Store holds one cluster TLS identity. Freeze stops changes while CDS takes
// the one-time handoff snapshot.
type Store struct {
	mu     sync.RWMutex
	state  Snapshot
	frozen bool
}

// NewStore creates a new cluster identity. It does not create a certificate.
func NewStore(random io.Reader) (*Store, error) {
	if random == nil {
		random = rand.Reader
	}
	s := Snapshot{
		Schema:          Schema,
		Version:         1,
		TLSKeySeed:      make([]byte, SeedSize),
		ACMEAccountSeed: make([]byte, SeedSize),
	}
	if _, err := io.ReadFull(random, s.TLSKeySeed); err != nil {
		return nil, fmt.Errorf("generate cluster TLS key seed: %w", err)
	}
	if _, err := io.ReadFull(random, s.ACMEAccountSeed); err != nil {
		return nil, fmt.Errorf("generate ACME account seed: %w", err)
	}
	return &Store{state: s}, nil
}

// NewStoreFromSnapshot restores state received through the secure CDS
// handoff. The caller must finish this step before it reports CDS as Ready.
func NewStoreFromSnapshot(s Snapshot) (*Store, error) {
	if err := ValidateSnapshot(s); err != nil {
		return nil, err
	}
	return &Store{state: cloneSnapshot(s)}, nil
}

// ValidateSnapshot rejects incomplete or inconsistent protected state.
func ValidateSnapshot(s Snapshot) error {
	if s.Schema != Schema {
		return fmt.Errorf("tee-webpki schema %q is not %q", s.Schema, Schema)
	}
	if s.Version == 0 {
		return fmt.Errorf("tee-webpki version must be positive")
	}
	if len(s.TLSKeySeed) != SeedSize {
		return fmt.Errorf("tee-webpki TLS key seed length = %d, want %d", len(s.TLSKeySeed), SeedSize)
	}
	if len(s.ACMEAccountSeed) != SeedSize {
		return fmt.Errorf("tee-webpki ACME account seed length = %d, want %d", len(s.ACMEAccountSeed), SeedSize)
	}
	if len(s.CertificatePEM) > MaxCertificate {
		return fmt.Errorf("tee-webpki certificate is too large")
	}
	if len(s.CSRPEM) > MaxCertificate {
		return fmt.Errorf("tee-webpki CSR is too large")
	}
	if len(s.ACMEState) > MaxACMEState {
		return fmt.Errorf("tee-webpki ACME state is too large")
	}
	if len(s.CertificatePEM) > 0 {
		key, err := PrivateKey(s.TLSKeySeed)
		if err != nil {
			return err
		}
		if _, err := ValidateCertificate(s.CertificatePEM, &key.PublicKey); err != nil {
			return err
		}
	}
	if len(s.CSRPEM) > 0 {
		key, err := PrivateKey(s.TLSKeySeed)
		if err != nil {
			return err
		}
		if err := ValidateCSR(s.CSRPEM, &key.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

// Snapshot returns an independent copy of the protected state.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.state)
}

// Freeze returns the final snapshot and stops later certificate changes. The
// active CDS uses this before it gives state to one successor.
func (s *Store) Freeze() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frozen = true
	return cloneSnapshot(s.state)
}

// UpdatePublicState installs a public certificate and ACME renewal data. The
// certificate must match the protected TLS key. Version is a compare-and-swap
// value, which prevents two renewal writers from losing an update.
func (s *Store) UpdatePublicState(update PublicUpdate) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen {
		return Snapshot{}, fmt.Errorf("tee-webpki state is frozen for CDS handoff")
	}
	if update.Version != s.state.Version {
		return Snapshot{}, fmt.Errorf("tee-webpki version conflict: got %d, want %d", update.Version, s.state.Version)
	}
	if len(update.CertificatePEM) > MaxCertificate || len(update.CSRPEM) > MaxCertificate {
		return Snapshot{}, fmt.Errorf("tee-webpki certificate or CSR is too large")
	}
	if len(update.ACMEState) > MaxACMEState {
		return Snapshot{}, fmt.Errorf("tee-webpki ACME state is too large")
	}
	key, err := PrivateKey(s.state.TLSKeySeed)
	if err != nil {
		return Snapshot{}, err
	}
	if len(update.CertificatePEM) > 0 {
		if _, err := ValidateCertificate(update.CertificatePEM, &key.PublicKey); err != nil {
			return Snapshot{}, err
		}
	}
	if len(update.CSRPEM) > 0 {
		if err := ValidateCSR(update.CSRPEM, &key.PublicKey); err != nil {
			return Snapshot{}, err
		}
	}
	if len(update.CertificatePEM) == 0 && len(update.CSRPEM) == 0 && len(update.ACMEState) == 0 {
		return Snapshot{}, fmt.Errorf("tee-webpki public update is empty")
	}
	s.state.Version++
	if len(update.CertificatePEM) > 0 {
		s.state.CertificatePEM = append([]byte(nil), update.CertificatePEM...)
	}
	if len(update.CSRPEM) > 0 {
		s.state.CSRPEM = append([]byte(nil), update.CSRPEM...)
	}
	// A CSR-only update must not erase renewal state. The operator can replace
	// ACME state when it supplies a non-empty value.
	if len(update.ACMEState) > 0 {
		s.state.ACMEState = append(json.RawMessage(nil), update.ACMEState...)
	}
	return cloneSnapshot(s.state), nil
}

// PrivateKey derives the same P-256 key inside each attested tls-lb replica.
// The seed is never placed in a Kubernetes object.
func PrivateKey(seed []byte) (*ecdsa.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("TLS key seed length = %d, want %d", len(seed), SeedSize)
	}
	curve := elliptic.P256()
	h := sha256.Sum256(append([]byte("c8s/tee-webpki/tls-key/v1\x00"), seed...))
	n := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).SetBytes(h[:])
	d.Mod(d, n)
	d.Add(d, big.NewInt(1))
	key := &ecdsa.PrivateKey{D: d}
	key.Curve = curve
	key.X, key.Y = curve.ScalarBaseMult(d.Bytes())
	return key, nil
}

// ValidateCertificate parses a PEM chain and verifies that its leaf uses pub.
// WebPKI chain validation stays with the tls-lb replica because it owns the
// system trust store and the requested DNS names.
func ValidateCertificate(chainPEM []byte, pub *ecdsa.PublicKey) (*x509.Certificate, error) {
	var leaf *x509.Certificate
	rest := chainPEM
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("tee-webpki certificate PEM contains %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse tee-webpki certificate: %w", err)
		}
		if leaf == nil {
			leaf = cert
		}
	}
	if leaf == nil || len(rest) != 0 {
		return nil, fmt.Errorf("tee-webpki certificate PEM is invalid")
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil || !leafPub.Equal(pub) {
		return nil, fmt.Errorf("tee-webpki certificate does not match the protected TLS key")
	}
	return leaf, nil
}

// ValidateCSR verifies a public CSR against the protected TLS key.
func ValidateCSR(csrPEM []byte, pub *ecdsa.PublicKey) error {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return fmt.Errorf("tee-webpki CSR PEM is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse tee-webpki CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("verify tee-webpki CSR: %w", err)
	}
	csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil || !csrPub.Equal(pub) {
		return fmt.Errorf("tee-webpki CSR does not match the protected TLS key")
	}
	return nil
}

func cloneSnapshot(s Snapshot) Snapshot {
	s.TLSKeySeed = append([]byte(nil), s.TLSKeySeed...)
	s.CertificatePEM = append([]byte(nil), s.CertificatePEM...)
	s.CSRPEM = append([]byte(nil), s.CSRPEM...)
	s.ACMEAccountSeed = append([]byte(nil), s.ACMEAccountSeed...)
	s.ACMEState = append(json.RawMessage(nil), s.ACMEState...)
	return s
}
