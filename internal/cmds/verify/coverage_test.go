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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

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

func TestNormalizeTarget_Errors(t *testing.T) {
	if _, _, err := normalizeTarget("https://\x7f", 443); err == nil {
		t.Error("control character URL should fail to parse")
	}
	if _, _, err := normalizeTarget("https:///path-only", 443); err == nil {
		t.Error("URL without a host should be rejected")
	}
}

func TestMinTCBFromCfg(t *testing.T) {
	if got := minTCBFromCfg(config{}); got != nil {
		t.Errorf("all-zero flags should yield nil, got %+v", got)
	}
	got := minTCBFromCfg(config{minTCBBootloader: 1, minTCBTEE: 2, minTCBSNP: 3, minTCBMicrocode: 4})
	if got == nil || got.Bootloader != 1 || got.Tee != 2 || got.Snp != 3 || got.Microcode != 4 {
		t.Errorf("minTCBFromCfg = %+v, want 1/2/3/4", got)
	}
}

func TestBuildPolicy_FileInputs(t *testing.T) {
	dir := t.TempDir()
	measHex := strings.Repeat("ab", 48)

	t.Run("measurements file", func(t *testing.T) {
		path := filepath.Join(dir, "measurements.txt")
		if err := os.WriteFile(path, []byte(measHex+"\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		policy, err := buildPolicy(config{measurementsFile: path})
		if err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
		if len(policy.Measurements) != 1 || hex.EncodeToString(policy.Measurements[0]) != measHex {
			t.Errorf("measurements = %v", policy.Measurements)
		}
	})

	t.Run("measurements file missing", func(t *testing.T) {
		if _, err := buildPolicy(config{measurementsFile: filepath.Join(dir, "absent")}); err == nil {
			t.Error("missing --measurements-file must fail")
		}
	})

	t.Run("bad measurement hex", func(t *testing.T) {
		if _, err := buildPolicy(config{measurements: []string{"zz"}}); err == nil {
			t.Error("non-hex measurement must fail")
		}
	})

	t.Run("operator keys PEM", func(t *testing.T) {
		pubPEM, _ := operatorPubPEM(t)
		path := filepath.Join(dir, "op.pub")
		if err := os.WriteFile(path, pubPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildPolicy(config{operatorKeys: path}); err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
		digest, err := expectedOperatorKeysDigest(config{operatorKeys: path})
		if err != nil {
			t.Fatalf("expectedOperatorKeysDigest: %v", err)
		}
		if len(digest) == 0 {
			t.Error("no digest computed from --operator-keys")
		}
	})

	t.Run("operator keys missing file", func(t *testing.T) {
		if _, err := buildPolicy(config{operatorKeys: filepath.Join(dir, "absent")}); err == nil {
			t.Error("missing --operator-keys must fail")
		}
	})

	t.Run("operator keys bad PEM", func(t *testing.T) {
		path := filepath.Join(dir, "bad.pub")
		if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildPolicy(config{operatorKeys: path}); err == nil {
			t.Error("unparseable --operator-keys must fail")
		}
	})

	t.Run("sandbox id needs the mesh CA", func(t *testing.T) {
		// The ID is vouched by CDS's signature on the leaf, so pinning it
		// without checking that signature would pin an attacker-chosen string.
		if _, err := buildPolicy(config{sandboxID: "abc123"}); err == nil {
			t.Error("--sandbox-id without --mesh-ca must fail")
		}
	})

	t.Run("malformed sandbox id", func(t *testing.T) {
		if _, err := buildPolicy(config{sandboxID: "bad id!", meshCA: "unused"}); err == nil {
			t.Error("malformed --sandbox-id must fail")
		}
	})
}

func TestGatherOperatorKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("skipped for non-cds kinds and file targets", func(t *testing.T) {
		got := gatherOperatorKeys(ctx, config{kind: "lb", url: "x"}, &evidence{})
		if !strings.Contains(got.note, "skipped") || got.fingerprints != nil || got.fetchErr != nil {
			t.Errorf("non-cds kind must skip the cross-check without fetching, got %+v", got)
		}
		if got := gatherOperatorKeys(ctx, config{kind: "cds"}, &evidence{}); got.note != "" {
			t.Errorf("no url should be a no-op, got %+v", got)
		}
	})

	t.Run("no serving cert to bind to", func(t *testing.T) {
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: "cds.example.com"}, &evidence{})
		if got.note == "" || got.fingerprints != nil {
			t.Errorf("no attested cert must skip the fetch with a note, got %+v", got)
		}
	})

	t.Run("bad target", func(t *testing.T) {
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: "https://\x7f"}, &evidence{certSHA256: "aa"})
		if !strings.HasPrefix(got.note, "not fetched:") || got.fetchErr != nil {
			t.Errorf("unparseable target should degrade to a note, got %+v", got)
		}
	})

	t.Run("fetches and binds to the attested cert", func(t *testing.T) {
		pubPEM, wantFP := operatorPubPEM(t)
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/operator-keys" {
				http.NotFound(w, r)
				return
			}
			w.Write(pubPEM)
		})
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: base, timeout: 5 * time.Second}, &evidence{certSHA256: certSHA})
		if got.fetchErr != nil || got.note != "" {
			t.Fatalf("fetch failed: %+v", got)
		}
		if len(got.fingerprints) != 1 || got.fingerprints[0] != wantFP {
			t.Errorf("fingerprints = %v, want [%s]", got.fingerprints, wantFP)
		}
	})

	t.Run("fetch failure records fetchErr", func(t *testing.T) {
		base, _ := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: base, timeout: 5 * time.Second}, &evidence{certSHA256: strings.Repeat("ab", 32)})
		if got.fetchErr == nil || !strings.HasPrefix(got.note, "not fetched:") {
			t.Errorf("expected a recorded fetch error, got %+v", got)
		}
	})
}

func TestFetchOperatorKeyFingerprints_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("no attested cert pin", func(t *testing.T) {
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, "https://x", "", "", time.Second); err == nil {
			t.Error("empty wantCertSHA256 must be rejected")
		}
	})

	t.Run("non-200 non-404", func(t *testing.T) {
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, base, "", certSHA, 5*time.Second); err == nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("expected a 500 error, got %v", err)
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write(bytes.Repeat([]byte("A"), maxOperatorKeysBytes+2))
		})
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, base, "", certSHA, 5*time.Second); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("expected an oversize rejection, got %v", err)
		}
	})

	t.Run("unparseable body", func(t *testing.T) {
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not pem at all"))
		})
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, base, "", certSHA, 5*time.Second); err == nil || !strings.Contains(err.Error(), "parse /operator-keys") {
			t.Errorf("expected a parse error, got %v", err)
		}
	})
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

func TestGatherEvidence_ModesAndErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("ratls-cert mode", func(t *testing.T) {
		srv := attestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ev, err := gatherEvidence(ctx, config{url: srv.URL, mode: "ratls-cert", timeout: 5 * time.Second}, nil)
		if err != nil {
			t.Fatalf("ratls-cert mode: %v", err)
		}
		if !strings.Contains(ev.source, "RA-TLS serving certificate") {
			t.Errorf("source = %q, want the cert path", ev.source)
		}
	})

	t.Run("attest-pq mode", func(t *testing.T) {
		report := bytes.Repeat([]byte{0x01}, 64)
		x := bytes.Repeat([]byte{0x02}, overenc.X25519PubBytes)
		m := bytes.Repeat([]byte{0x03}, overenc.MLKEM768EKBytes)
		id := mintEndpointIdentity(t)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/c8s/attest-pq" {
				http.NotFound(w, r)
				return
			}
			nonce, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("nonce"))
			w.Write(buildEndpointJSON(t, id, nonce, report, []byte("vcek"), x, m))
		}))
		defer srv.Close()
		ev, err := gatherEvidence(ctx, config{url: srv.URL, mode: "attest-pq", timeout: 5 * time.Second}, nil)
		if err != nil {
			t.Fatalf("attest-pq mode: %v", err)
		}
		if !ev.fresh {
			t.Error("endpoint evidence should be fresh")
		}
	})

	t.Run("auto falls through to the cert path on discovery parse failure", func(t *testing.T) {
		// auto tries discovery first; serve a discovery doc that is not JSON so
		// parsing fails. That failure is not a security error, so auto must fall
		// through to the cert path (which then errors on the self-signed test
		// cert) rather than aborting with a security verdict.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer srv.Close()
		_, err := gatherEvidence(ctx, config{url: srv.URL, kind: "auto", timeout: 5 * time.Second}, nil)
		if err == nil || isSecurityError(err) {
			t.Fatalf("parse failure should fall through to the cert path, got %v", err)
		}
	})
}

func TestEvidenceFromEndpointJSON_Malformed(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, overenc.X25519PubBytes)
	m := bytes.Repeat([]byte{0x03}, overenc.MLKEM768EKBytes)
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

func TestEvidenceFromDiscovery_Malformed(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)

	if _, err := evidenceFromDiscovery([]byte("not json"), "t"); err == nil {
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
	if _, err := evidenceFromDiscovery(noEvidence, "t"); err == nil || !strings.Contains(err.Error(), "no attestation.evidence") {
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
	if _, err := evidenceFromDiscovery(badChallenge, "t"); err == nil || !strings.Contains(err.Error(), "decode challenge") {
		t.Errorf("bad challenge base64 should fail, got %v", err)
	}

	garbageCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
	if _, err := evidenceFromDiscovery(discoveryDocWith(t, garbageCert, []byte("c"), `{"attestation_report":"AAAA"}`), "t"); err == nil || !strings.Contains(err.Error(), "parse cds cert") {
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
	ev, err := evidenceFromDiscovery(data, "t")
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want the snp default for a platform-less doc", ev.platform)
	}
}

func TestFetchDiscoveryDoc(t *testing.T) {
	ctx := context.Background()

	t.Run("bad base URL", func(t *testing.T) {
		if _, _, err := fetchDiscoveryDoc(ctx, "https://\x7f", "", "", time.Second); err == nil {
			t.Error("unparseable base must fail")
		}
	})

	t.Run("connection refused is a connectError", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		base := srv.URL
		srv.Close()
		_, _, err := fetchDiscoveryDoc(ctx, base, "", "", time.Second)
		if err == nil || !isConnectError(err) {
			t.Fatalf("expected connectError, got %v", err)
		}
	})
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
		// endpoint parser reports its own error.
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

func TestRun_UsageAndGatherFailures(t *testing.T) {
	t.Run("retired attestation-endpoint mode is a usage error, not an alias", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{url: "x", mode: "attestation-endpoint"}, &out, &errOut)
		if code != exitUsage || !strings.Contains(errOut.String(), "attest-pq") {
			t.Errorf("code = %d, want %d with the valid mode list; stderr: %s", code, exitUsage, errOut.String())
		}
	})

	t.Run("unknown mode is a usage error", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), config{url: "x", mode: "bogus"}, &out, &errOut); code != exitUsage {
			t.Errorf("code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
		}
	})

	t.Run("policy error", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), config{minTCBSNP: 256, url: "x"}, &out, &errOut); code != exitUsage {
			t.Errorf("code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
		}
	})

	t.Run("bad expected-report-data", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{fromFile: "whatever", expectedRDHex: "zz"}, &out, &errOut)
		if code != exitUsage || !strings.Contains(errOut.String(), "expected-report-data") {
			t.Errorf("code = %d, stderr: %s", code, errOut.String())
		}
	})

	t.Run("missing from-file exits no-evidence", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{fromFile: filepath.Join(t.TempDir(), "absent")}, &out, &errOut)
		if code != exitNoEvidence || !strings.Contains(errOut.String(), "could not obtain evidence") {
			t.Errorf("code = %d, stderr: %s", code, errOut.String())
		}
	})
}
