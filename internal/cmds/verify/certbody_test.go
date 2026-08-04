package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// mintAttestedLeaf builds a self-issued cert with a genuine (fake-SNP)
// attestation extension, an embedded public key from holder, a signature by
// signer, and the given validity. signer != holder models an altered body
// re-signed by an attacker who does not hold the attested key.
func mintAttestedLeaf(t *testing.T, holder *ecdsa.PublicKey, signer *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	attExt, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(11),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{attExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, holder, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// An altered self-signed body under a real attestation extension must never
// produce evidence: the extension binds only the key, so the self-signature
// is the only thing authenticating subject/serial/validity.
func TestEvidenceFromCertRejectsResignedBody(t *testing.T) {
	now := time.Now()
	holder, signer := testKey(t), testKey(t)
	cert := mintAttestedLeaf(t, &holder.PublicKey, signer, now.Add(-time.Hour), now.Add(time.Hour))

	_, err := evidenceFromCert(cert, "test")
	if err == nil || !strings.Contains(err.Error(), "does not verify with its own key") {
		t.Fatalf("want self-signature rejection, got %v", err)
	}
	if !isSecurityError(err) {
		t.Fatalf("an altered body is a security failure (no auto-mode fall-through), got %T", err)
	}
}

func TestEvidenceFromCertValidity(t *testing.T) {
	now := time.Now()
	key := testKey(t)

	t.Run("future NotBefore beyond skew rejected", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key,
			now.Add(certutil.LeafValiditySkew+time.Minute), now.Add(2*time.Hour))
		_, err := evidenceFromCert(cert, "test")
		if err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("want NotBefore rejection, got %v", err)
		}
		if !isSecurityError(err) {
			t.Fatalf("want a security error, got %T", err)
		}
	})

	t.Run("NotBefore within skew accepted", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key,
			now.Add(certutil.LeafValiditySkew-time.Minute), now.Add(2*time.Hour))
		if _, err := evidenceFromCert(cert, "test"); err != nil {
			t.Fatalf("NotBefore within the documented skew must pass: %v", err)
		}
	})

	t.Run("expired NotAfter rejected", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Minute))
		_, err := evidenceFromCert(cert, "test")
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want NotAfter rejection, got %v", err)
		}
	})

	// The binding note must say what bounds a replay: these certs carry no
	// nonce, so validity is the only freshness bound.
	t.Run("replay bounded only by validity is documented in the binding", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		ev, err := evidenceFromCert(cert, "test")
		if err != nil {
			t.Fatal(err)
		}
		if ev.fresh {
			t.Error("cert evidence must not claim freshness")
		}
		if !strings.Contains(ev.bindingNote, "replayable within the certificate validity window") {
			t.Errorf("bindingNote = %q, want it to state the replay bound", ev.bindingNote)
		}
	})
}

// The discovery path parses the same class of certificate and must apply the
// same body rules, and its retained leaf unlocks the CA-vouched pins.
func TestEvidenceFromDiscoveryAuthenticatesCertBody(t *testing.T) {
	now := time.Now()
	key := testKey(t)

	t.Run("expired discovery cert rejected", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Minute))
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(cert.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		_, err := evidenceFromDiscovery(doc, "test")
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want NotAfter rejection, got %v", err)
		}
	})

	t.Run("re-signed discovery cert rejected", func(t *testing.T) {
		signer := testKey(t)
		cert := mintAttestedLeaf(t, &key.PublicKey, signer, now.Add(-time.Hour), now.Add(time.Hour))
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(cert.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		if _, err := evidenceFromDiscovery(doc, "test"); err == nil {
			t.Fatal("want self-signature rejection on the discovery cert")
		}
	})

	t.Run("valid discovery cert is retained as the leaf", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(cert.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		ev, err := evidenceFromDiscovery(doc, "test")
		if err != nil {
			t.Fatal(err)
		}
		if ev.leaf == nil {
			t.Fatal("discovery evidence must retain the leaf so --mesh-ca/--sandbox-id/--workload can check it")
		}
		if !ev.leafSelfIssued {
			t.Error("a self-issued discovery cert must be recorded as such")
		}
	})
}

// The verdict says what authenticates the body fields, in each class.
func TestDescribeCertBody(t *testing.T) {
	self := &evidence{leafSelfIssued: true}
	if got := describeCertBody(config{}, self); !strings.Contains(got, "own attested key") {
		t.Errorf("self-signed note = %q", got)
	}
	caSigned := &evidence{leafSelfIssued: false}
	if got := describeCertBody(config{}, caSigned); !strings.Contains(got, "UNAUTHENTICATED") {
		t.Errorf("CA-signed note without --mesh-ca = %q, must flag the unauthenticated body", got)
	}
	if got := describeCertBody(config{meshCA: "ca.pem"}, caSigned); !strings.Contains(got, "--mesh-ca") ||
		strings.Contains(got, "UNAUTHENTICATED") {
		t.Errorf("CA-signed note with --mesh-ca = %q", got)
	}
}
