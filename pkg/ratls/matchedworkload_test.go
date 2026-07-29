package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testMatched() *MatchedWorkload {
	return &MatchedWorkload{
		Names:         []string{"kimi-k3", "sglang-dev"},
		EntriesDigest: bytes.Repeat([]byte{0x5a}, ClaimsDigestSize),
	}
}

func TestMatchedWorkloadRoundtrip(t *testing.T) {
	ext, err := MarshalMatchedWorkloadExtension(testMatched())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !ext.Id.Equal(OIDMatchedWorkload) {
		t.Fatalf("wrong OID: %v", ext.Id)
	}
	got, err := UnmarshalMatchedWorkload(ext.Value)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Names) != 2 || got.Names[0] != "kimi-k3" || got.Names[1] != "sglang-dev" {
		t.Fatalf("names round-trip: %v", got.Names)
	}
	if !bytes.Equal(got.EntriesDigest, testMatched().EntriesDigest) {
		t.Fatal("digest round-trip mismatch")
	}
	if !got.Ambiguous() {
		t.Fatal("two names must report ambiguous")
	}
	single := &MatchedWorkload{Names: []string{"kimi-k3"}, EntriesDigest: testMatched().EntriesDigest}
	if single.Ambiguous() {
		t.Fatal("one name must not report ambiguous")
	}
}

func TestMatchedWorkloadValidation(t *testing.T) {
	base := testMatched()

	for name, mutate := range map[string]func(*MatchedWorkload){
		"no names":        func(m *MatchedWorkload) { m.Names = nil },
		"unsorted":        func(m *MatchedWorkload) { m.Names = []string{"b", "a"} },
		"duplicate":       func(m *MatchedWorkload) { m.Names = []string{"a", "a"} },
		"comma in name":   func(m *MatchedWorkload) { m.Names = []string{"a,b"} },
		"leading dot":     func(m *MatchedWorkload) { m.Names = []string{".hidden"} },
		"empty name":      func(m *MatchedWorkload) { m.Names = []string{""} },
		"short digest":    func(m *MatchedWorkload) { m.EntriesDigest = m.EntriesDigest[:16] },
		"nil digest":      func(m *MatchedWorkload) { m.EntriesDigest = nil },
		"oversize digest": func(m *MatchedWorkload) { m.EntriesDigest = append(m.EntriesDigest, 0) },
	} {
		m := &MatchedWorkload{
			Names:         append([]string(nil), base.Names...),
			EntriesDigest: append([]byte(nil), base.EntriesDigest...),
		}
		mutate(m)
		if _, err := MarshalMatchedWorkloadExtension(m); err == nil {
			t.Errorf("%s: marshal must fail", name)
		}
	}
}

func TestMatchedWorkloadUnmarshalRejectsNonCanonical(t *testing.T) {
	ext, err := MarshalMatchedWorkloadExtension(testMatched())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Trailing bytes.
	if _, err := UnmarshalMatchedWorkload(append(append([]byte(nil), ext.Value...), 0xde, 0xad)); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
	// Non-minimal outer length (re-frame the SEQUENCE with a long-form length).
	inner := ext.Value[2:] // strip 0x30 <len>
	nonMinimal := append([]byte{0x30, 0x81, byte(len(inner))}, inner...)
	if _, err := UnmarshalMatchedWorkload(nonMinimal); err == nil {
		t.Fatal("non-minimal encoding must be rejected (byte-exact round-trip)")
	}
	// Unknown version.
	bad := append([]byte(nil), ext.Value...)
	// version rides as INTEGER 1 right after the SEQUENCE header: 0x02 0x01 0x01
	if bad[2] != 0x02 || bad[3] != 0x01 {
		t.Fatalf("unexpected DER layout: % x", bad[:6])
	}
	bad[4] = 0x07
	if _, err := UnmarshalMatchedWorkload(bad); err == nil {
		t.Fatal("unknown version must be rejected")
	}
}

func TestMatchedWorkloadFromCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	ext, err := MarshalMatchedWorkloadExtension(testMatched())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "leaf"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	got, err := MatchedWorkloadFromCert(cert)
	if err != nil {
		t.Fatalf("from cert: %v", err)
	}
	if got == nil || len(got.Names) != 2 {
		t.Fatalf("stamp not recovered: %+v", got)
	}

	// A cert without the extension yields nil, nil — absence is not an error.
	plain := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "plain"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	plainDER, err := x509.CreateCertificate(rand.Reader, plain, plain, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create plain cert: %v", err)
	}
	plainCert, err := x509.ParseCertificate(plainDER)
	if err != nil {
		t.Fatalf("parse plain cert: %v", err)
	}
	if got, err := MatchedWorkloadFromCert(plainCert); err != nil || got != nil {
		t.Fatalf("absent extension must be nil,nil; got %+v, %v", got, err)
	}
}
