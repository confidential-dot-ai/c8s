package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- newAzureConfig ---

func TestNewAzureConfigRefusesRedirects(t *testing.T) {
	c := newAzureConfig(testCred, nil)
	req, _ := http.NewRequest(http.MethodGet, "https://elsewhere.example", nil)
	if err := c.client.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

// --- parseMappings malformed shapes ---

func TestParseMappingsMalformed(t *testing.T) {
	for _, raw := range []string{
		`[]`,                              // not an object
		`{`,                               // truncated
		`{"/a": 5}`,                       // value not an object
		`{"/a": {"vault": "v"}`,           // truncated object
		`{"/a": {"vault": 1, "name": 2}}`, // wrong field types
		`{"a"}`,                           // bare key
	} {
		if _, err := parseMappings(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s: accepted", raw)
		}
	}
	if m, err := parseMappings(json.RawMessage(`{}`)); err != nil || len(m) != 0 {
		t.Fatalf("empty object: %v %v", m, err)
	}
}

// --- handler failure paths ---

func TestExternalConfigMethodNotAllowed(t *testing.T) {
	h := externalHandler(NewExternalBackend(nil, nil, 64), NewMemoryStore(8, 64))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, ExternalRoute, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestExternalConfigClearFailure(t *testing.T) {
	fail := func(map[string]AzureMapping) error { return os.ErrPermission }
	h := externalHandler(NewExternalBackend(nil, fail, 64), NewMemoryStore(8, 64))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute,
		strings.NewReader(`{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{},"mappings":{}}`)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestExternalConfigApplyFailure(t *testing.T) {
	fail := func(map[string]AzureMapping) error { return os.ErrPermission }
	h := externalHandler(NewExternalBackend(nil, fail, 64), NewMemoryStore(8, 64))
	doc := `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},"mappings":{"/a":{"vault":"https://v.vault.azure.net","name":"s"}}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(doc)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestExternalConfigNilLogger(t *testing.T) {
	h := ExternalConfigHandler{Backend: NewExternalBackend(nil, nil, 64), Mem: NewMemoryStore(8, 64)}
	if h.logger() == nil {
		t.Fatal("nil logger")
	}
}

// --- LoadExternalMappings error paths ---

func TestLoadExternalMappingsPersistFails(t *testing.T) {
	_, persist, err := LoadExternalMappings(filepath.Join(t.TempDir(), "no-such-dir", "allowlist.db"))
	if err != nil {
		t.Fatal(err)
	}
	if persist == nil {
		t.Fatal("persist hook nil for a real path")
	}
	if err := persist(map[string]AzureMapping{}); err == nil {
		t.Fatal("persist into a nonexistent directory must fail")
	}
}

func TestLoadExternalMappingsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be: ReadFile fails, not NotExist.
	if err := os.Mkdir(filepath.Join(dir, externalMappingsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadExternalMappings(filepath.Join(dir, "allowlist.db")); err == nil {
		t.Fatal("a mappings path that is a directory must fail loud")
	}
}

// --- Fetch on an unmapped path is a programming error, not a fetch ---

func TestExternalBackendFetchUnmapped(t *testing.T) {
	b := NewExternalBackend(nil, nil, 64)
	if _, err := b.Fetch(context.Background(), "/nope"); err == nil {
		t.Fatal("Fetch on an unmapped path must fail")
	}
}

// --- azure client error shapes ---

func TestAzureFetchMalformedBundle(t *testing.T) {
	f := newFakeAzure(t)
	f.rawSecretBody = `not json`
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v, want a decode failure", err)
	}
}

func TestAzureFetchMissingValueField(t *testing.T) {
	f := newFakeAzure(t)
	f.rawSecretBody = `{"id":"x"}`
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil || !strings.Contains(err.Error(), "no value") {
		t.Fatalf("err = %v, want a missing-value failure", err)
	}
}

func TestAzureTokenMalformedJSON(t *testing.T) {
	f := newFakeAzure(t)
	f.tokenBody = `not json`
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v, want a token decode failure", err)
	}
}

func TestAzureTokenMissingFields(t *testing.T) {
	f := newFakeAzure(t)
	f.tokenBody = `{"access_token":"","expires_in":0}`
	c := f.config(testCred, map[string]AzureMapping{"/a": {Vault: f.srv.URL, Name: "s1"}})
	if _, err := c.fetch(context.Background(), "/a"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v, want a missing-fields failure", err)
	}
}

// transportErr passes non-URL errors through.
func TestTransportErrPassthrough(t *testing.T) {
	if got := transportErr(os.ErrNotExist); got != os.ErrNotExist {
		t.Fatalf("transportErr = %v", got)
	}
}
