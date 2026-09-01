package teewebpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func TestStoreSharesOneKeyAndRejectsWrongCertificate(t *testing.T) {
	store, err := NewStore(bytes.NewReader(bytes.Repeat([]byte{0x41}, 2*SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	keyA, _ := PrivateKey(state.TLSKeySeed)
	keyB, _ := PrivateKey(state.TLSKeySeed)
	if !keyA.Equal(keyB) {
		t.Fatal("one seed did not derive one cluster TLS key")
	}

	certificate := selfSignedServerCertificate(t, keyA, "api.example")
	updated, err := store.UpdatePublicState(PublicUpdate{Version: state.Version, CertificatePEM: certificate})
	if err != nil {
		t.Fatalf("update matching certificate: %v", err)
	}
	if updated.Version != state.Version+1 {
		t.Fatalf("version = %d, want %d", updated.Version, state.Version+1)
	}

	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongCertificate := selfSignedServerCertificate(t, wrong, "api.example")
	if _, err := store.UpdatePublicState(PublicUpdate{Version: updated.Version, CertificatePEM: wrongCertificate}); err == nil {
		t.Fatal("store accepted a certificate for another private key")
	}
}

func TestStoreFreezeStopsRenewalChanges(t *testing.T) {
	store, err := NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Freeze()
	key, _ := PrivateKey(state.TLSKeySeed)
	if _, err := store.UpdatePublicState(PublicUpdate{
		Version:        state.Version,
		CertificatePEM: selfSignedServerCertificate(t, key, "api.example"),
	}); err == nil {
		t.Fatal("frozen handoff state accepted a renewal")
	}
}

func TestCSRUpdateKeepsACMEState(t *testing.T) {
	store, err := NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	key, err := PrivateKey(state.TLSKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"api.example"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.UpdatePublicState(PublicUpdate{
		Version:   state.Version,
		CSRPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		ACMEState: json.RawMessage(`{"order":"pending"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.UpdatePublicState(PublicUpdate{
		Version: first.Version,
		CSRPEM:  first.CSRPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.ACMEState, first.ACMEState) {
		t.Fatal("CSR-only update erased ACME state")
	}
}

func TestHandlerReleasesStateOnlyToExpectedMatchedWorkload(t *testing.T) {
	store, _ := NewStore(nil)
	h := Handler{Store: store, ExpectedWorkload: "c8s-tls-lb"}

	request := httptest.NewRequest(http.MethodGet, Route, nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("request without mesh identity = %d, want 403", response.Code)
	}

	leaf := matchedWorkloadCertificate(t, "c8s-tls-lb")
	request = httptest.NewRequest(http.MethodGet, Route, nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("admitted tls-lb = %d: %s", response.Code, response.Body.String())
	}
	var got Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TLSKeySeed, store.Snapshot().TLSKeySeed) {
		t.Fatal("handler did not return the protected cluster TLS seed")
	}

	rollout := matchedWorkloadCertificateWithIdentity(t, "c8s-tls-lb-2026-09-01", "c8s-tls-lb")
	request = httptest.NewRequest(http.MethodGet, Route, nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{rollout}, VerifiedChains: [][]*x509.Certificate{{rollout}}}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("rollout policy with stable tls-lb identity = %d: %s", response.Code, response.Body.String())
	}

	wrong := matchedWorkloadCertificate(t, "another-workload")
	request = httptest.NewRequest(http.MethodGet, Route, nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{wrong}, VerifiedChains: [][]*x509.Certificate{{wrong}}}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong admitted workload = %d, want 403", response.Code)
	}
}

func TestServeCSRPublishesVersionAndDisablesCaching(t *testing.T) {
	store, err := NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	key, err := PrivateKey(state.TLSKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"api.example"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.UpdatePublicState(PublicUpdate{
		Version: state.Version,
		CSRPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	Handler{Store: store}.ServeCSR(response, httptest.NewRequest(http.MethodGet, CSRRoute, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("ServeCSR = HTTP %d: %s", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get(VersionHeader), fmt.Sprint(state.Version); got != want {
		t.Fatalf("%s = %q, want %q", VersionHeader, got, want)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestOperatorCertificateUpdateUsesAuthorizerAndRejectsTrailingJSON(t *testing.T) {
	store, err := NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	key, err := PrivateKey(state.TLSKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(PublicUpdate{
		Version:        state.Version,
		CertificatePEM: selfSignedServerCertificate(t, key, "api.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized := 0
	handler := OperatorHandler{
		Store: store,
		Authorize: func(_ *http.Request, got []byte) error {
			authorized++
			if !bytes.Equal(got, body) {
				t.Fatalf("authorized body differs from request")
			}
			return nil
		},
	}
	request := httptest.NewRequest(http.MethodPut, CertificateRoute, bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || authorized != 1 {
		t.Fatalf("authorized update = HTTP %d, authorize calls %d", response.Code, authorized)
	}

	updated := store.Snapshot()
	trailingBody, err := json.Marshal(PublicUpdate{
		Version:        updated.Version,
		CertificatePEM: updated.CertificatePEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	trailingBody = append(trailingBody, []byte("{}")...)
	handler.Authorize = func(_ *http.Request, _ []byte) error { return nil }
	request = httptest.NewRequest(http.MethodPut, CertificateRoute, bytes.NewReader(trailingBody))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON update = HTTP %d, want 400", response.Code)
	}
}

func matchedWorkloadCertificate(t *testing.T, name string) *x509.Certificate {
	return matchedWorkloadCertificateWithIdentity(t, name, "")
}

func matchedWorkloadCertificateWithIdentity(t *testing.T, name, identity string) *x509.Certificate {
	t.Helper()
	ext, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{
		Name:             name,
		Identity:         identity,
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: name},
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func selfSignedServerCertificate(t *testing.T, key *ecdsa.PrivateKey, name string) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
