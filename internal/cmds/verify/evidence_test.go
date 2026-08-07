package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func discoveryDocWith(t *testing.T, certPEM string, challenge []byte, evidence string) []byte {
	t.Helper()
	doc := map[string]any{
		"cds_tls": map[string]any{"certificate_pem": certPEM},
		"attestation": map[string]any{
			"challenge": base64.StdEncoding.EncodeToString(challenge),
			"platform":  "snp",
			"evidence":  json.RawMessage(evidence),
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery doc: %v", err)
	}
	return data
}

// attestedTLSServer starts an httptest TLS server whose serving certificate is
// a (fake-report) RA-TLS attested cert, so cert-mode gathering succeeds.
func attestedTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestGatherFromRATLSCert(t *testing.T) {
	t.Run("attested serving cert", func(t *testing.T) {
		srv := attestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := strings.TrimPrefix(srv.URL, "https://")
		ev, err := gatherFromRATLSCert(context.Background(), addr, "", 5*time.Second)
		if err != nil {
			t.Fatalf("gatherFromRATLSCert: %v", err)
		}
		if ev.platform != "snp" || ev.fresh {
			t.Errorf("platform=%q fresh=%t, want snp / not fresh", ev.platform, ev.fresh)
		}
		if ev.certSHA256 == "" {
			t.Error("certSHA256 not recorded")
		}
		if !strings.Contains(ev.source, addr) {
			t.Errorf("source = %q, want the dialed address", ev.source)
		}
	})

	t.Run("plain cert without RA-TLS extension", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer srv.Close()
		_, err := gatherFromRATLSCert(context.Background(), strings.TrimPrefix(srv.URL, "https://"), "", 5*time.Second)
		if err == nil || isConnectError(err) {
			t.Fatalf("non-attested cert must fail as a non-connect error, got %v", err)
		}
	})

	t.Run("dial failure is a connectError", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := strings.TrimPrefix(srv.URL, "https://")
		srv.Close()
		_, err := gatherFromRATLSCert(context.Background(), addr, "", time.Second)
		if err == nil || !isConnectError(err) {
			t.Fatalf("expected connectError on refused dial, got %v", err)
		}
	})
}

func TestEvidenceFromEndpointJSON_Malformed(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0x03}, overenc.MLKEM768EKBytes)
	// A genuine attest-pq body, so the only thing wrong in each case below is
	// the one field the mutation corrupts.
	id := mintEndpointIdentity(t)

	mutate := func(field, value string) []byte {
		var obj map[string]any
		if err := json.Unmarshal(buildEndpointJSON(t, id, nonce, report, []byte("vcek"), x, m), &obj); err != nil {
			t.Fatal(err)
		}
		switch field {
		case "nonce":
			obj["nonce"] = value
		case "x25519":
			obj["session_pubkey"].(map[string]any)["x25519"] = value
		case "mlkem768":
			obj["session_pubkey"].(map[string]any)["mlkem768"] = value
		}
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	if _, err := evidenceFromEndpointJSON([]byte("not json"), nonce, "t"); err == nil {
		t.Error("non-JSON must fail")
	}
	if _, err := evidenceFromEndpointJSON([]byte(`{"nonce":"AA"}`), nonce, "t"); err == nil {
		t.Error("missing evidence must fail")
	}
	if _, err := evidenceFromEndpointJSON(mutate("nonce", "!!!"), nonce, "t"); err == nil || !strings.Contains(err.Error(), "decode nonce") {
		t.Errorf("bad nonce base64 should fail decoding, got %v", err)
	}
	if _, err := evidenceFromEndpointJSON(mutate("x25519", "!!!"), nonce, "t"); err == nil || !strings.Contains(err.Error(), "x25519") {
		t.Errorf("bad x25519 base64 should fail decoding, got %v", err)
	}
	if _, err := evidenceFromEndpointJSON(mutate("mlkem768", "!!!"), nonce, "t"); err == nil || !strings.Contains(err.Error(), "mlkem768") {
		t.Errorf("bad mlkem768 base64 should fail decoding, got %v", err)
	}
}

func TestGatherFromFile(t *testing.T) {
	t.Run("attested certificate PEM", func(t *testing.T) {
		cert := attestedCert(t, "")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		ev, err := gatherFromFile(pemBytes, nil, "file")
		if err != nil {
			t.Fatalf("gatherFromFile: %v", err)
		}
		wantSum := sha256.Sum256(cert.Raw)
		if ev.certSHA256 != hex.EncodeToString(wantSum[:]) {
			t.Errorf("certSHA256 = %q, want the cert digest", ev.certSHA256)
		}
	})

	t.Run("unparseable certificate DER", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
		if _, err := gatherFromFile(pemBytes, nil, "file"); err == nil || !strings.Contains(err.Error(), "parse certificate") {
			t.Errorf("expected a parse error, got %v", err)
		}
	})

	t.Run("override falls through to endpoint parsing", func(t *testing.T) {
		// Not bare evidence (no evidence object), so the bare path fails and the
		// endpoint parser reports its own error. The version tag has to be the
		// attest-pq binding or the parser stops at the version check instead.
		payload := []byte(`{"version":"` + types.BindingAttestPQ + `"}`)
		if _, err := gatherFromFile(payload, []byte{0x01}, "file"); err == nil || !strings.Contains(err.Error(), "no evidence") {
			t.Errorf("expected the endpoint parser's error, got %v", err)
		}
	})
}

func TestEvidenceFromBareJSON_Errors(t *testing.T) {
	if _, err := evidenceFromBareJSON([]byte("not json"), []byte{0x01}, "t"); err == nil {
		t.Error("non-JSON must fail")
	}
	if _, err := evidenceFromBareJSON([]byte(`{"platform":"snp"}`), []byte{0x01}, "t"); err == nil {
		t.Error("missing evidence must fail")
	}
	ev, err := evidenceFromBareJSON([]byte(`{"evidence":{"attestation_report":"AAAA"}}`), []byte{0x01}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want the snp default", ev.platform)
	}
}
