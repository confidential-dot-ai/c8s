package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticCAExtensions_AttestFailureAborts(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staticCAExtensions(context.Background(), srv.URL, make([]byte, 32))(&key.PublicKey); err == nil {
		t.Fatal("an unattested CA key was stamped")
	}
}
