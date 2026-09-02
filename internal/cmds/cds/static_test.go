package cds

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/initdata"
)

// fakeAttestationAPI answers /attest with a stub SNP envelope and /verify with
// a verdict whose init_data claim is claimHex — the shape checkInitDataSeal
// reads, with the hardware chain stubbed out.
func fakeAttestationAPI(t *testing.T, claimHex string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/attest"):
			_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": map[string]any{"attestation_report": "AA=="}})
		case strings.HasSuffix(r.URL.Path, "/verify"):
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{
				"platform": "snp", "signature_valid": true, "report_data_match": true,
				"claims": map[string]any{"launch_digest": strings.Repeat("ab", 48), "init_data": claimHex},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckInitDataSeal(t *testing.T) {
	sealed := make([]byte, 32)
	sealed[0] = 0x42
	built, err := initdata.New(map[string]string{
		initdata.KeyRole:                   initdata.RoleCDS,
		initdata.KeyCDSAllowlistSeedSHA256: hex.EncodeToString(sealed),
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(t.TempDir(), "initdata.toml")
	if err := os.WriteFile(doc, built.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { initDataDocumentPath = initdata.GuestDocumentPath })
	initDataDocumentPath = doc

	committed := hex.EncodeToString(built.Digest[:])
	if err := checkInitDataSeal(context.Background(), fakeAttestationAPI(t, committed).URL, sealed); err != nil {
		t.Fatalf("launch-committed document naming the sealed digest must pass: %v", err)
	}
	// TDX reports MRCONFIGID as the digest zero-padded to 48 bytes.
	if err := checkInitDataSeal(context.Background(), fakeAttestationAPI(t, committed+strings.Repeat("00", 16)).URL, sealed); err != nil {
		t.Fatalf("zero-padded MRCONFIGID must pass: %v", err)
	}

	other := make([]byte, 32)
	other[0] = 0x99
	if err := checkInitDataSeal(context.Background(), fakeAttestationAPI(t, committed).URL, other); err == nil {
		t.Fatal("a document naming another digest must refuse the seal")
	}
	if err := checkInitDataSeal(context.Background(), fakeAttestationAPI(t, strings.Repeat("00", 32)).URL, sealed); err == nil {
		t.Fatal("a claim that is not the document's digest must refuse the seal")
	}
	initDataDocumentPath = filepath.Join(t.TempDir(), "missing.toml")
	if err := checkInitDataSeal(context.Background(), fakeAttestationAPI(t, committed).URL, sealed); err == nil {
		t.Fatal("no launch-committed document must refuse the seal")
	}
}
