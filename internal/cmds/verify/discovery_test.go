package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
