package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEvidenceFromDiscovery_Malformed(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)

	if _, err := evidenceFromDiscovery([]byte("not json"), "t", leafTrust{}, nil); err == nil {
		t.Error("non-JSON must fail")
	}

	var obj map[string]any
	good := discoveryDocWith(t, certPEM, []byte("c"), `{"attestation_report":"AAAA"}`)
	if err := json.Unmarshal(good, &obj); err != nil {
		t.Fatal(err)
	}

	delete(obj["attestation"].(map[string]any), "evidence")
	noEvidence, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromDiscovery(noEvidence, "t", leafTrust{}, nil); err == nil || !strings.Contains(err.Error(), "no attestation.evidence") {
		t.Errorf("missing evidence should fail, got %v", err)
	}
	if err := json.Unmarshal(good, &obj); err != nil {
		t.Fatal(err)
	}
	obj["attestation"].(map[string]any)["challenge"] = "%%%not-base64%%%"
	badChallenge, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromDiscovery(badChallenge, "t", leafTrust{}, nil); err == nil || !strings.Contains(err.Error(), "decode challenge") {
		t.Errorf("bad challenge base64 should fail, got %v", err)
	}

	garbageCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
	if _, err := evidenceFromDiscovery(discoveryDocWith(t, garbageCert, []byte("c"), `{"attestation_report":"AAAA"}`), "t", leafTrust{}, nil); err == nil || !strings.Contains(err.Error(), "parse cds cert") {
		t.Errorf("unparseable cert DER should fail, got %v", err)
	}
}

func TestEvidenceFromDiscovery_DefaultsPlatformToSNP(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	doc := map[string]any{
		"cds_tls": map[string]any{"certificate_pem": certPEM},
		"attestation": map[string]any{
			"challenge": base64.StdEncoding.EncodeToString([]byte("c")),
			"evidence":  json.RawMessage(`{"attestation_report":"AAAA"}`),
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidenceFromDiscovery(data, "t", leafTrust{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want the snp default for a platform-less doc", ev.platform)
	}
}

func TestGatherFromDiscoveryConnectErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("bad base URL", func(t *testing.T) {
		if _, err := gatherFromDiscovery(ctx, "https://\x7f", "", "", time.Second, leafTrust{}); err == nil {
			t.Error("unparseable base must fail")
		}
	})

	t.Run("connection refused is a connectError", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		base := srv.URL
		srv.Close()
		_, err := gatherFromDiscovery(ctx, base, "", "", time.Second, leafTrust{})
		if err == nil || !isConnectError(err) {
			t.Fatalf("expected connectError, got %v", err)
		}
	})
}

// selfSignedServerCert mints a throwaway self-signed certificate and returns
// its PEM encoding plus a tls.Certificate a test server can present.
func selfSignedServerCert(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lb"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// discoveryServer starts a TLS server presenting serverCert and serving doc.
func discoveryServer(t *testing.T, serverCert tls.Certificate, doc []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(doc)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The discovery gather probes the live handshake on https targets: the
// verdict about the front door's serving key keys on what the handshake
// presented, not on the document's declared public_tls.mode — the lying-host
// case (claims cds, serves another key) and the honest webpki case both
// record an unbound door, and only the attested cert on the wire records a
// bound one.
func TestGatherFromDiscoveryProbesFrontDoor(t *testing.T) {
	challenge := []byte("issuance-challenge")
	stubEvidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`

	attestedPEM, attestedCert := selfSignedServerCert(t) // the key the document attests
	_, otherCert := selfSignedServerCert(t)              // a WebPKI stand-in
	docClaims := func(mode string) []byte {
		return discoveryDocWithPublicTLS(t, mode, attestedPEM, challenge, stubEvidence)
	}

	t.Run("handshake presents the attested cert", func(t *testing.T) {
		srv := discoveryServer(t, attestedCert, docClaims("cds"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested {
			t.Errorf("frontDoor = %v, want attested", ev.frontDoor)
		}
		if !strings.Contains(ev.bindingNote, "live handshake") {
			t.Errorf("bindingNote = %q, want it to record the observed handshake", ev.bindingNote)
		}
	})

	t.Run("lying host: claims cds, serves another cert", func(t *testing.T) {
		srv := discoveryServer(t, otherCert, docClaims("cds"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorOther {
			t.Fatalf("frontDoor = %v, want other", ev.frontDoor)
		}
		served := sha256.Sum256(otherCert.Certificate[0])
		if ev.frontDoorCertSHA256 != hex.EncodeToString(served[:]) {
			t.Errorf("frontDoorCertSHA256 = %q, want the served cert's digest %x", ev.frontDoorCertSHA256, served)
		}
		// The verdict is partial, never verified: the door clients reach is
		// not attestation-bound, however the document declares itself.
		oc := snpVerifiedOutcome(t, config{}, ev)
		if oc.Verified || !oc.Partial || verdictExitCode(oc) != exitPartial {
			t.Errorf("verified=%v partial=%v exit=%d, want a partial verdict", oc.Verified, oc.Partial, verdictExitCode(oc))
		}
	})

	t.Run("honest webpki: declared and served unbound", func(t *testing.T) {
		srv := discoveryServer(t, otherCert, docClaims("webpki"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorOther {
			t.Errorf("frontDoor = %v, want other", ev.frontDoor)
		}
	})

	t.Run("declared webpki but serves the attested cert", func(t *testing.T) {
		srv := discoveryServer(t, attestedCert, docClaims("webpki"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested {
			t.Errorf("frontDoor = %v, want attested: the observed handshake governs, not the declaration", ev.frontDoor)
		}
	})

	t.Run("non-TLS target leaves the door unobserved", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(docClaims("cds"))
		}))
		t.Cleanup(srv.Close)
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorUnobserved {
			t.Errorf("frontDoor = %v, want unobserved", ev.frontDoor)
		}
	})

	t.Run("redirect on the discovery path is a fetch failure", func(t *testing.T) {
		srv := discoveryServer(t, attestedCert, docClaims("cds"))
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		})
		_, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err == nil || !isConnectError(err) {
			t.Fatalf("a redirect must fail as a fetch (connect) error, got %v", err)
		}
	})
}

// A discovery document's CA-vouched serving cert (the chart's shape: issued
// by the CDS mesh CA) is authenticated by the live handshake when it presents
// byte-identically that cert — the same possession backstop as the RA-TLS
// path — so a live door needs no --mesh-ca. A door serving a different cert
// gets no such backstop and fails closed.
func TestDiscoveryHandshakeAuthenticatesCAVouchedBody(t *testing.T) {
	challenge := []byte("issuance-challenge")
	stubEvidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`

	id := mintEndpointIdentity(t) // CA-signed leaf, the CDS-issued serving cert's shape
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.leaf.Raw}))
	leafTLSCert := tls.Certificate{Certificate: [][]byte{id.leaf.Raw}, PrivateKey: id.key}
	doc := discoveryDocWithPublicTLS(t, "cds", leafPEM, challenge, stubEvidence)

	t.Run("handshake presenting the attested CA-vouched leaf needs no --mesh-ca", func(t *testing.T) {
		srv := discoveryServer(t, leafTLSCert, doc)
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatalf("a live door presenting the attested leaf must authenticate its body: %v", err)
		}
		if ev.frontDoor != frontDoorAttested || !ev.leafKeyProven {
			t.Errorf("frontDoor = %v leafKeyProven = %v, want attested / proven", ev.frontDoor, ev.leafKeyProven)
		}
		if got := describeCertBody(config{}, ev); !strings.Contains(got, "live TLS handshake") {
			t.Errorf("cert-body note = %q, want the possession branch", got)
		}
	})

	t.Run("a pinned mesh CA stays the body authentication on a match", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AddCert(id.ca)
		srv := discoveryServer(t, leafTLSCert, doc)
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{meshCA: pool})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested || !ev.leafChainVerified {
			t.Errorf("frontDoor = %v leafChainVerified = %v, want attested / chain-verified", ev.frontDoor, ev.leafChainVerified)
		}
		if got := describeCertBody(config{}, ev); !strings.Contains(got, "verified issuing chain") {
			t.Errorf("cert-body note = %q, want the verified-chain branch", got)
		}
	})

	t.Run("a door serving another cert gets no possession backstop", func(t *testing.T) {
		_, otherCert := selfSignedServerCert(t)
		srv := discoveryServer(t, otherCert, doc)
		_, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err == nil || !isSecurityError(err) {
			t.Fatalf("an unauthenticated CA-vouched body must fail closed, got %v", err)
		}
		if !strings.Contains(err.Error(), "--mesh-ca") {
			t.Errorf("error = %q, want it to name the flag that fixes it", err)
		}
	})
}
