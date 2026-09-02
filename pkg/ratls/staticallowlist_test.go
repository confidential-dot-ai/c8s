package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func testStaticAllowlist() *StaticAllowlist {
	return &StaticAllowlist{AllowlistDigest: bytes.Repeat([]byte{0x22}, 32)}
}

// goldenStaticAllowlistDER is the one canonical encoding of {v1, 0x22*32} —
// shared with the JS verifier so two parsers cannot drift.
const goldenStaticAllowlistDER = "30250201010420" +
	"2222222222222222222222222222222222222222222222222222222222222222"

func TestStaticAllowlist_GoldenVector(t *testing.T) {
	ext, err := MarshalStaticAllowlistExtension(testStaticAllowlist())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ext.Value); got != goldenStaticAllowlistDER {
		t.Fatalf("DER = %s, want %s", got, goldenStaticAllowlistDER)
	}
	if ext.Critical {
		t.Fatal("static-allowlist extension must be non-critical")
	}
	if !ext.Id.Equal(OIDStaticAllowlist) {
		t.Fatalf("OID = %v", ext.Id)
	}

	der, _ := hex.DecodeString(goldenStaticAllowlistDER)
	s, err := UnmarshalStaticAllowlist(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.AllowlistDigest, testStaticAllowlist().AllowlistDigest) {
		t.Fatalf("round-trip mismatch: %x", s.AllowlistDigest)
	}
}

func TestStaticAllowlist_MarshalRejectsInvalid(t *testing.T) {
	for name, digest := range map[string][]byte{
		"digest short": bytes.Repeat([]byte{0x22}, 31),
		"digest long":  bytes.Repeat([]byte{0x22}, 33),
		"digest nil":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := MarshalStaticAllowlistExtension(&StaticAllowlist{AllowlistDigest: digest}); err == nil {
				t.Fatal("MarshalStaticAllowlistExtension accepted an invalid digest")
			}
		})
	}
}

func TestStaticAllowlist_UnmarshalRejectsDamage(t *testing.T) {
	golden, _ := hex.DecodeString(goldenStaticAllowlistDER)

	trailing := append(append([]byte(nil), golden...), 0x00)

	// Same fields under version 2.
	v2 := append([]byte(nil), golden...)
	v2[4] = 0x02

	// A long-form length for the outer SEQUENCE: same value, different bytes.
	nonMinimal := append([]byte{0x30, 0x81, golden[1]}, golden[2:]...)

	// An extra INTEGER field appended inside the SEQUENCE.
	extraField := append(append([]byte(nil), golden...), 0x02, 0x01, 0x01)
	extraField[1] += 3

	for name, der := range map[string][]byte{
		"trailing bytes":     trailing,
		"unknown version":    v2,
		"non-minimal length": nonMinimal,
		"extra field":        extraField,
		"empty":              {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalStaticAllowlist(der); err == nil {
				t.Fatal("UnmarshalStaticAllowlist accepted damaged DER")
			}
		})
	}
}

// selfSignedWithExtensions builds a throwaway self-signed certificate carrying
// the given extra extensions, for FromCert tests.
func selfSignedWithExtensions(t *testing.T, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestStaticAllowlistFromCert(t *testing.T) {
	ext, err := MarshalStaticAllowlistExtension(testStaticAllowlist())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("absent", func(t *testing.T) {
		s, err := StaticAllowlistFromCert(selfSignedWithExtensions(t, nil))
		if err != nil || s != nil {
			t.Fatalf("StaticAllowlistFromCert(no ext) = %v, %v; want nil, nil", s, err)
		}
	})

	t.Run("present", func(t *testing.T) {
		s, err := StaticAllowlistFromCert(selfSignedWithExtensions(t, []pkix.Extension{ext}))
		if err != nil {
			t.Fatal(err)
		}
		if s == nil || !bytes.Equal(s.AllowlistDigest, testStaticAllowlist().AllowlistDigest) {
			t.Fatalf("StaticAllowlistFromCert = %+v", s)
		}
	})

	// x509.CreateCertificate refuses duplicate or damaged extensions itself,
	// so the hostile shapes are exercised on the parsed-extension view a
	// verifier actually reads.
	t.Run("duplicated", func(t *testing.T) {
		cert := &x509.Certificate{Extensions: []pkix.Extension{ext, ext}}
		if _, err := StaticAllowlistFromCert(cert); err == nil {
			t.Fatal("StaticAllowlistFromCert accepted a duplicated extension")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: OIDStaticAllowlist, Value: []byte{0x30, 0x00}}}}
		if _, err := StaticAllowlistFromCert(cert); err == nil {
			t.Fatal("StaticAllowlistFromCert accepted a malformed extension")
		}
	})
}
