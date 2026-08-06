package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// mintLeaf builds a self-issued cert whose embedded public key is pub but
// whose signature comes from signer — signer != holder models a body altered
// and re-signed by an attacker who does not hold the attested key.
func mintLeaf(t *testing.T, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAuthenticateLeafBodySelfSigned(t *testing.T) {
	now := time.Now()
	key := genKey(t)

	t.Run("genuine self-signed accepted", func(t *testing.T) {
		cert := mintLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		body, err := AuthenticateLeafBody(cert, now)
		if err != nil {
			t.Fatalf("AuthenticateLeafBody: %v", err)
		}
		if body != BodySelfSigned {
			t.Errorf("body = %v, want BodySelfSigned for a self-issued cert", body)
		}
	})

	t.Run("re-signed body rejected", func(t *testing.T) {
		// The embedded (attested) key is key's, but the signature is another
		// key's: an altered body under a real attestation extension.
		other := genKey(t)
		cert := mintLeaf(t, &key.PublicKey, other, now.Add(-time.Hour), now.Add(time.Hour))
		if _, err := AuthenticateLeafBody(cert, now); err == nil ||
			!strings.Contains(err.Error(), "does not verify with its own key") {
			t.Fatalf("want self-signature rejection, got %v", err)
		}
	})

	t.Run("tampered TBS rejected", func(t *testing.T) {
		cert := mintLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		// Flip one byte of the signed body after issuance.
		cert.RawTBSCertificate = append([]byte(nil), cert.RawTBSCertificate...)
		cert.RawTBSCertificate[len(cert.RawTBSCertificate)-1] ^= 0x01
		if _, err := AuthenticateLeafBody(cert, now); err == nil {
			t.Fatal("want rejection of a tampered TBS body")
		}
	})
}

// The self-signature check is reached only when RawIssuer == RawSubject, and
// both DNs are written by whoever produced the bytes. Altering the Issuer by
// one byte therefore skips it entirely — and x509.ParseCertificate verifies no
// signature, so the Signature field can be junk. The classification must
// report that nothing authenticated the body, never BodySelfSigned.
func TestAuthenticateLeafBodyForgedIssuerIsNotSelfSigned(t *testing.T) {
	now := time.Now()
	key := genKey(t)

	// The attacker's mint: same (attested) public key, an Issuer DN one word
	// off the Subject, and NotAfter decades out.
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf-issuer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(500000 * time.Hour),
		IsCA:         true,
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(500000 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, genKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing ever checked this signature; prove it by destroying it.
	cert.Signature = bytes.Repeat([]byte{0xff}, len(cert.Signature))

	body, err := AuthenticateLeafBody(cert, now)
	if err != nil {
		t.Fatalf("AuthenticateLeafBody: %v", err)
	}
	if body == BodySelfSigned {
		t.Fatal("an issuer != subject body claimed self-signed authentication; its signature was never checked")
	}
	if body != BodyCAVouched {
		t.Fatalf("body = %v, want BodyCAVouched", body)
	}
	// The zero value must be the unauthenticated one, so a caller that drops
	// the classification into a fresh variable fails closed rather than open.
	var zero BodyAuthentication
	if zero != BodyCAVouched {
		t.Error("the zero BodyAuthentication must be the unauthenticated class")
	}
}

func TestAuthenticateLeafBodyValidity(t *testing.T) {
	now := time.Now()
	key := genKey(t)

	t.Run("future NotBefore beyond skew rejected", func(t *testing.T) {
		cert := mintLeaf(t, &key.PublicKey, key, now.Add(LeafValiditySkew+time.Minute), now.Add(2*time.Hour))
		if _, err := AuthenticateLeafBody(cert, now); err == nil ||
			!strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("want NotBefore rejection, got %v", err)
		}
	})

	t.Run("NotBefore within skew accepted", func(t *testing.T) {
		cert := mintLeaf(t, &key.PublicKey, key, now.Add(LeafValiditySkew-time.Minute), now.Add(2*time.Hour))
		if _, err := AuthenticateLeafBody(cert, now); err != nil {
			t.Fatalf("NotBefore within the skew allowance must pass: %v", err)
		}
	})

	t.Run("expired NotAfter rejected with no allowance", func(t *testing.T) {
		cert := mintLeaf(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Second))
		if _, err := AuthenticateLeafBody(cert, now); err == nil ||
			!strings.Contains(err.Error(), "expired") {
			t.Fatalf("want NotAfter rejection, got %v", err)
		}
	})

	// A nonce-free certificate is replayable for exactly as long as it
	// validates: inside the window there is nothing to distinguish a replay,
	// and the bound is the validity itself.
	t.Run("replay bounded only by validity", func(t *testing.T) {
		cert := mintLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		if _, err := AuthenticateLeafBody(cert, now.Add(59*time.Minute)); err != nil {
			t.Fatalf("still inside validity — a replay is indistinguishable and must pass: %v", err)
		}
		if _, err := AuthenticateLeafBody(cert, now.Add(61*time.Minute)); err == nil {
			t.Fatal("past NotAfter the replay window must close")
		}
	})
}

func TestAuthenticateLeafBodyCASigned(t *testing.T) {
	now := time.Now()
	caKey := genKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := genKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// A CA-issued leaf is not self-issued: validity is enforced here, and body
	// authentication is the caller's CA-chain check.
	body, err := AuthenticateLeafBody(leaf, now)
	if err != nil {
		t.Fatalf("AuthenticateLeafBody: %v", err)
	}
	if body != BodyCAVouched {
		t.Errorf("body = %v, want BodyCAVouched for a CA-issued leaf", body)
	}
	if _, err := AuthenticateLeafBody(leaf, now.Add(2*time.Hour)); err == nil {
		t.Fatal("validity must be enforced on CA-issued leaves too")
	}
}
