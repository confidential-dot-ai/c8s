package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func selfSignedForTest(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "observe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

// The observer must never see a peer whose verification failed. Republishing a
// certificate recorded here labels it "verified by a workload we attested", so
// firing on a rejected peer would publish an unverified certificate under that
// label — the exact confusion this ordering exists to prevent.
func TestObserverSkippedWhenVerificationFails(t *testing.T) {
	called := false
	cb := observeVerifiedPeer(
		func([][]byte, [][]*x509.Certificate) error { return errors.New("attestation failed") },
		func(*x509.Certificate) { called = true },
	)

	if err := cb([][]byte{[]byte("whatever")}, nil); err == nil {
		t.Fatal("wrapper swallowed the verification error")
	}
	if called {
		t.Fatal("observer fired for a peer that failed verification")
	}
}

// On success it must receive the peer that actually verified.
func TestObserverReceivesVerifiedPeer(t *testing.T) {
	leaf, _ := selfSignedForTest(t)

	var got *x509.Certificate
	cb := observeVerifiedPeer(
		func([][]byte, [][]*x509.Certificate) error { return nil },
		func(c *x509.Certificate) { got = c },
	)

	if err := cb([][]byte{leaf.Raw}, nil); err != nil {
		t.Fatalf("wrapper returned error on success: %v", err)
	}
	if got == nil {
		t.Fatal("observer never fired for a verified peer")
	}
	if !got.Equal(leaf) {
		t.Fatal("observer received a different certificate than the peer presented")
	}
}

// No observer configured must leave the callback exactly as it was.
func TestObserverNilIsPassThrough(t *testing.T) {
	sentinel := errors.New("inner")
	inner := func([][]byte, [][]*x509.Certificate) error { return sentinel }
	if got := observeVerifiedPeer(inner, nil); got == nil {
		t.Fatal("nil observer produced a nil callback")
	} else if err := got(nil, nil); !errors.Is(err, sentinel) {
		t.Fatalf("nil observer altered behaviour: %v", err)
	}
}
