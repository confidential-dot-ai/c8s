package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	pkgsecrets "github.com/confidential-dot-ai/c8s/pkg/secrets"
)

// fakeBroker is a self-contained fake CDS secrets broker: its own CA, a
// broker signing leaf, an encryption key, and a map store. It speaks the real
// wire protocol so the CLI client is tested end to end.
type fakeBroker struct {
	caPEM      []byte
	identity   pkgsecrets.BrokerIdentity
	encPriv    []byte
	signingKey *ecdsa.PrivateKey

	mu    sync.Mutex
	store map[string][]byte
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "c8s-secrets-broker"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}

	encPriv, encPub, err := pkgsecrets.GenerateX25519()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	encSig, err := pkgsecrets.SignEncryptionPubkey(leafKey, encPub)
	if err != nil {
		t.Fatalf("enc sig: %v", err)
	}

	return &fakeBroker{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		identity: pkgsecrets.BrokerIdentity{
			SigningLeafPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			CAChainPEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
			EncryptionPubkey:    base64.StdEncoding.EncodeToString(encPub),
			EncryptionPubkeySig: encSig,
		},
		encPriv:    encPriv,
		signingKey: leafKey,
		store:      map[string][]byte{},
	}
}

func (f *fakeBroker) handler(t *testing.T) http.Handler {
	r := chi.NewRouter()
	r.Get("/ca", func(w http.ResponseWriter, _ *http.Request) { w.Write(f.caPEM) })
	r.Get("/secrets/broker-identity", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(f.identity)
	})
	r.Put("/secrets/entries/{entry}/paths/*", func(w http.ResponseWriter, req *http.Request) {
		entry, p := chi.URLParam(req, "entry"), "/"+chi.URLParam(req, "*")
		var wrapped pkgsecrets.Wrapped
		if err := json.NewDecoder(req.Body).Decode(&wrapped); err != nil {
			http.Error(w, "bad body", http.StatusUnprocessableEntity)
			return
		}
		value, err := pkgsecrets.Unwrap(f.encPriv, pkgsecrets.DepositAAD(entry, p), wrapped)
		if err != nil {
			http.Error(w, "unwrap failed", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.store[entry+"\x00"+p] = value
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	r.Get("/secrets/entries/{entry}/paths/*", func(w http.ResponseWriter, req *http.Request) {
		entry, p := chi.URLParam(req, "entry"), "/"+chi.URLParam(req, "*")
		pub, err := base64.StdEncoding.DecodeString(req.URL.Query().Get("pubkey"))
		if err != nil {
			http.Error(w, "bad pubkey", http.StatusUnprocessableEntity)
			return
		}
		f.mu.Lock()
		value, ok := f.store[entry+"\x00"+p]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		wrapped, err := pkgsecrets.Wrap(pub, value, pkgsecrets.DepositAAD(entry, p))
		if err != nil {
			http.Error(w, "wrap failed", http.StatusInternalServerError)
			return
		}
		sig, err := pkgsecrets.SignResponse(f.signingKey, wrapped)
		if err != nil {
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(pkgsecrets.FetchResponse{Payload: wrapped, Signature: sig})
	})
	r.Delete("/secrets/entries/{entry}/paths/*", func(w http.ResponseWriter, req *http.Request) {
		entry, p := chi.URLParam(req, "entry"), "/"+chi.URLParam(req, "*")
		f.mu.Lock()
		delete(f.store, entry+"\x00"+p)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return r
}

func testOperatorSigner(t *testing.T) *operatorauth.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("operator key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// TestCLIRoundTrip drives the real CLI client against a fake broker: identity
// verify → put → get → delete, end to end over the real wire protocol.
func TestCLIRoundTrip(t *testing.T) {
	fake := newFakeBroker(t)
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	signer := testOperatorSigner(t)

	caPEM, err := getBytes(context.Background(), srv.Client(), srv.URL+"/ca")
	if err != nil {
		t.Fatalf("fetch ca: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse ca")
	}
	identityJSON, err := getBytes(context.Background(), srv.Client(), srv.URL+"/secrets/broker-identity")
	if err != nil {
		t.Fatalf("fetch identity: %v", err)
	}
	bc, err := newBrokerClient(srv.Client(), srv.URL, roots, identityJSON)
	if err != nil {
		t.Fatalf("broker client: %v", err)
	}

	if err := bc.put(context.Background(), "vllm-llama", "/secrets/model/dek", []byte("the-dek"), signer); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := bc.get(context.Background(), "vllm-llama", "/secrets/model/dek", signer)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "the-dek" {
		t.Fatalf("got %q", got)
	}
	if err := bc.del(context.Background(), "vllm-llama", "/secrets/model/dek", signer); err != nil {
		t.Fatalf("del: %v", err)
	}
	if _, err := bc.get(context.Background(), "vllm-llama", "/secrets/model/dek", signer); err == nil {
		t.Fatal("get after delete succeeded")
	}
}

// TestBrokerClientRejectsWrongCA: an identity chained to a different root must fail.
func TestBrokerClientRejectsWrongCA(t *testing.T) {
	fake := newFakeBroker(t)
	other := newFakeBroker(t)
	identityJSON, _ := json.Marshal(fake.identity)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(other.caPEM)
	if _, err := newBrokerClient(&http.Client{}, "http://x", roots, identityJSON); err == nil {
		t.Fatal("identity from the wrong CA accepted")
	}
}

func TestReadValueArg(t *testing.T) {
	if v, _ := readValueArg("literal"); string(v) != "literal" {
		t.Fatalf("got %q", v)
	}
	f := t.TempDir() + "/v"
	if err := os.WriteFile(f, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	v, err := readValueArg("@" + f)
	if err != nil || string(v) != "from-file" {
		t.Fatalf("got %q err %v", v, err)
	}
}
