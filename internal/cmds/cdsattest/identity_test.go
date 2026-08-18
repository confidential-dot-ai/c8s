package cdsattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type testMeshIdentity struct {
	certFile string
	keyFile  string
	caFile   string
	leaf     *x509.Certificate
	ca       *x509.Certificate
	key      *ecdsa.PrivateKey
}

func writeTestMeshIdentity(t *testing.T) testMeshIdentity {
	t.Helper()
	now := time.Now()
	return writeTestMeshIdentityWithLeafValidity(t, now.Add(-time.Hour), now.Add(time.Hour))
}

// writeTestMeshIdentityWithLeafExtensions mints a mesh identity whose
// CA-signed leaf carries the given extra extensions (e.g. a matched-workload
// stamp for the /readyz gate).
func writeTestMeshIdentityWithLeafExtensions(t *testing.T, exts ...pkix.Extension) testMeshIdentity {
	t.Helper()
	now := time.Now()
	return writeTestMeshIdentityFull(t, now.Add(-time.Hour), now.Add(time.Hour), exts)
}

func writeTestMeshIdentityWithLeafValidity(t *testing.T, leafNotBefore, leafNotAfter time.Time) testMeshIdentity {
	t.Helper()
	return writeTestMeshIdentityFull(t, leafNotBefore, leafNotAfter, nil)
}

func writeTestMeshIdentityFull(t *testing.T, leafNotBefore, leafNotAfter time.Time, leafExts []pkix.Extension) testMeshIdentity {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "lb.c8s-system.svc"},
		NotBefore:       leafNotBefore,
		NotAfter:        leafNotAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: leafExts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, certFile, "CERTIFICATE", leafDER)
	writeTestPEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	writeTestPEM(t, caFile, "CERTIFICATE", caDER)
	return testMeshIdentity{certFile: certFile, keyFile: keyFile, caFile: caFile, leaf: leaf, ca: ca, key: leafKey}
}

func writeTestPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBoundAttestationAndChannel(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	provider := &capturingProvider{}
	srv := NewServer(Config{
		Backend:              EchoBackend{},
		Evidence:             provider,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	endpoint := ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(nonce)
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attestation status = %d, want 200", resp.StatusCode)
	}
	var bundle types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Version != types.BindingAttestPQ {
		t.Fatalf("unexpected bundle header: %+v", bundle)
	}
	if bundle.IdentityProof == nil || bundle.SessionPubKey == nil {
		t.Fatalf("bundle missing identity proof or session key: %+v", bundle)
	}

	x25519, err := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.X25519)
	if err != nil {
		t.Fatal(err)
	}
	mlkem, err := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	pub := overenc.PublicKey{X25519: x25519, MLKEM768: mlkem}
	wantReportData, err := overenc.IdentityTranscriptHash(pub, nonce, identity.leaf.Raw, identity.ca.Raw, overenc.UpstreamIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(provider.lastReportData, wantReportData) {
		t.Fatalf("report_data = %x, want identity transcript %x", provider.lastReportData, wantReportData)
	}

	leafHash := sha256.Sum256(identity.leaf.Raw)
	caHash := sha256.Sum256(identity.ca.Raw)
	if bundle.IdentityProof.LeafSHA256 != b64url(leafHash[:]) || bundle.IdentityProof.MeshCASHA256 != b64url(caHash[:]) {
		t.Fatalf("identity fingerprints do not match committed certificates: %+v", bundle.IdentityProof)
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.IdentityProof.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(wantReportData)
	if !ecdsa.VerifyASN1(&identity.key.PublicKey, digest[:], signature) {
		t.Fatal("mesh identity proof signature did not verify")
	}

	clientChannel, handshake, err := overenc.ClientAgree(pub, wantReportData)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := postHandshake(t, ts.URL, nonce, handshake)
	got := tunnel(t, ts.URL, clientChannel, sessionID, types.TunnelRequest{Method: "GET", Path: "/identity"})
	if got.Status != http.StatusOK {
		t.Fatalf("identity-bound tunnel response status = %d", got.Status)
	}
}

func postHandshake(t *testing.T, base string, nonce []byte, hs overenc.Handshake) string {
	t.Helper()
	body, err := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(hs.ClientX25519),
		MLKEMCt:      b64url(hs.MLKEMCiphertext),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(base+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handshake status = %d, want 200", resp.StatusCode)
	}
	var result types.HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.SessionID == "" {
		t.Fatal("identity-bound handshake returned no session id")
	}
	return result.SessionID
}

func TestIdentityBoundAttestationFailsClosedWithoutIdentity(t *testing.T) {
	srv := NewServer(Config{Evidence: &capturingProvider{}, Backend: EchoBackend{}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
}

func TestIdentityBoundAttestationFailsClosedOnInvalidConfiguredIdentity(t *testing.T) {
	srv := NewServer(Config{
		Backend:              EchoBackend{},
		Evidence:             &capturingProvider{},
		MeshIdentityCertFile: "/does/not/exist/cert.pem",
		MeshIdentityKeyFile:  "/does/not/exist/key.pem",
		MeshIdentityCAFile:   "/does/not/exist/ca.pem",
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestLoadMeshIdentityRejectsCopiedLeafWithoutPrivateKey(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalECPrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, identity.keyFile, "EC PRIVATE KEY", otherDER)
	if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
		t.Fatal("copied public leaf was accepted without its private key")
	}
}

func TestLoadMeshIdentityRejectsExpiredLeaf(t *testing.T) {
	now := time.Now()
	identity := writeTestMeshIdentityWithLeafValidity(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
		t.Fatal("expired mesh identity leaf was accepted")
	}
}

// The leaf's NotBefore gets exactly the repo-wide clock-skew allowance
// (certutil.LeafValiditySkew): a rotation-fresh leaf minted by a slightly
// fast clock loads, anything further in the future does not.
func TestLoadMeshIdentityLeafNotBeforeSkew(t *testing.T) {
	now := time.Now()

	beyond := writeTestMeshIdentityWithLeafValidity(t, now.Add(certutil.LeafValiditySkew+time.Minute), now.Add(3*time.Hour))
	if _, err := loadMeshIdentity(beyond.certFile, beyond.keyFile, beyond.caFile); err == nil {
		t.Fatal("mesh identity leaf with NotBefore beyond the skew allowance was accepted")
	}

	within := writeTestMeshIdentityWithLeafValidity(t, now.Add(certutil.LeafValiditySkew-time.Minute), now.Add(3*time.Hour))
	if _, err := loadMeshIdentity(within.certFile, within.keyFile, within.caFile); err != nil {
		t.Fatalf("mesh identity leaf with NotBefore within the skew allowance was refused: %v", err)
	}
}

// Every unusable credential configuration must refuse the load — a partial
// identity served anyway would sign transcripts with a credential the client
// cannot (or must not) chain.
func TestLoadMeshIdentityRejectsUnusableCredentials(t *testing.T) {
	t.Run("all three files are required", func(t *testing.T) {
		identity := writeTestMeshIdentity(t)
		for _, files := range [][3]string{
			{"", identity.keyFile, identity.caFile},
			{identity.certFile, "", identity.caFile},
			{identity.certFile, identity.keyFile, ""},
		} {
			if _, err := loadMeshIdentity(files[0], files[1], files[2]); err == nil || !strings.Contains(err.Error(), "required") {
				t.Fatalf("loadMeshIdentity(%q, %q, %q) = %v, want the required-files refusal", files[0], files[1], files[2], err)
			}
		}
	})

	t.Run("unreadable key file", func(t *testing.T) {
		identity := writeTestMeshIdentity(t)
		if err := os.Remove(identity.keyFile); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
			t.Fatal("missing key file was accepted")
		}
	})

	t.Run("unreadable CA file", func(t *testing.T) {
		identity := writeTestMeshIdentity(t)
		if err := os.Remove(identity.caFile); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
			t.Fatal("missing CA file was accepted")
		}
	})

	t.Run("non-ECDSA leaf key", func(t *testing.T) {
		// The proof algorithm is fixed (ecdsa-sha384), so an Ed25519 credential
		// cannot sign what clients verify and must be refused at load.
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "ed25519 leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		certFile := filepath.Join(dir, "cert.pem")
		keyFile := filepath.Join(dir, "key.pem")
		writeTestPEM(t, certFile, "CERTIFICATE", der)
		writeTestPEM(t, keyFile, "PRIVATE KEY", keyDER)
		if _, err := loadMeshIdentity(certFile, keyFile, certFile); err == nil || !strings.Contains(err.Error(), "ECDSA") {
			t.Fatalf("err = %v, want the ECDSA-only refusal", err)
		}
	})

	t.Run("CA bundle is not PEM certificates", func(t *testing.T) {
		identity := writeTestMeshIdentity(t)
		if err := os.WriteFile(identity.caFile, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
			t.Fatal("garbage CA bundle was accepted")
		}
	})

	t.Run("expired issuing CA", func(t *testing.T) {
		// The leaf window can be valid while the CA's is not; the whole chain
		// the endpoints serve must be inside its validity, so this fails closed.
		identity := writeExpiredCAMeshIdentity(t)
		if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil || !strings.Contains(err.Error(), "CA") {
			t.Fatalf("err = %v, want the expired-CA refusal", err)
		}
	})
}

// writeExpiredCAMeshIdentity mints a currently-valid leaf signed by a CA whose
// own validity window has already closed.
func writeExpiredCAMeshIdentity(t *testing.T) testMeshIdentity {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired mesh CA"},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(-time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lb.c8s-system.svc"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity := testMeshIdentity{
		certFile: filepath.Join(dir, "cert.pem"),
		keyFile:  filepath.Join(dir, "key.pem"),
		caFile:   filepath.Join(dir, "ca.pem"),
		leaf:     leaf,
		ca:       ca,
		key:      leafKey,
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, identity.certFile, "CERTIFICATE", leafDER)
	writeTestPEM(t, identity.keyFile, "EC PRIVATE KEY", keyDER)
	writeTestPEM(t, identity.caFile, "CERTIFICATE", caDER)
	return identity
}

// The endpoints take no pq or binding parameter: each path serves exactly one
// binding and there is nothing to negotiate. Any such param — even one naming
// the served binding — must get a loud 400 invalid_request on every route,
// including the retired /attestation path.
func TestAttestationRejectsQuerySelectors(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	certPath, _ := writeTestServingLeaf(t)
	srv := NewServer(Config{
		Backend:              EchoBackend{},
		Evidence:             &capturingProvider{},
		FrontDoorMode:        FrontDoorModeCDS,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for _, path := range []string{"/attest-pq", "/attest-lb", "/attestation"} {
		for _, query := range []string{
			"pq=false",
			"pq=true",
			"binding=over-encryption",
			"binding=unknown",
			"pq=false&binding=tls-cert",
			// Presence is the selector, not the value: an empty or bare
			// parameter is still a client negotiating, and it must be told.
			"pq=",
			"pq",
			"binding=",
			"binding",
		} {
			resp, err := http.Get(ts.URL + "/.well-known/c8s" + path + "?nonce=" + b64url(make([]byte, 32)) + "&" + query)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest {
				resp.Body.Close()
				t.Fatalf("%s?%s status = %d, want 400", path, query, resp.StatusCode)
			}
			if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
				t.Fatalf("%s?%s error code = %q", path, query, e.Error)
			}
		}
	}
}

// The retired pre-split endpoint returns the explicit versioned 400 — no
// alias, no downgrade — even for an otherwise well-formed request.
func TestRetiredAttestationEndpointReturns400(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q, want %q", e.Error, types.ErrorCodeInvalidRequest)
	}
}

func TestIdentityBoundAttestationRejectsWrongSizeNonce(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Backend:              EchoBackend{},
		Evidence:             &capturingProvider{},
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// The transcript frames an exact 32-byte nonce; both shorter and longer
	// values are refused rather than truncated or padded.
	for _, size := range []int{16, 31, 33} {
		resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(make([]byte, size)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%d-byte nonce status = %d, want 400", size, resp.StatusCode)
		}
	}
}
