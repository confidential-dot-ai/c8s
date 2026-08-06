package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- RoutingStore dispatch ---

func TestRoutingStoreUnmappedPathsUseMemory(t *testing.T) {
	mem := NewMemoryStore(8, 64)
	s := &RoutingStore{Mem: mem, External: NewExternalBackend(nil, nil, 64)}
	if _, _, err := s.PutIfAbsent(context.Background(), "/p", []byte("v"), OriginOperator); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), "/p")
	if err != nil || string(got) != "v" {
		t.Fatalf("Get = %q, %v", got, err)
	}
}

func TestRoutingStoreMappedWritesRefused(t *testing.T) {
	mem := NewMemoryStore(8, 64)
	backend := NewExternalBackend(map[string]AzureMapping{"/m": {Vault: "https://v.vault.azure.net", Name: "s"}}, nil, 64)
	s := &RoutingStore{Mem: mem, External: backend}

	if _, _, err := s.PutIfAbsent(context.Background(), "/m", []byte("v"), OriginWorkload); !errors.Is(err, ErrExternal) {
		t.Fatalf("PutIfAbsent = %v, want ErrExternal", err)
	}
	if _, err := s.Put(context.Background(), "/m", []byte("v"), OriginOperator); !errors.Is(err, ErrExternal) {
		t.Fatalf("Put = %v, want ErrExternal", err)
	}
	// The refusal must not fetch: Held carries no value.
	if _, err := s.Get(context.Background(), "/m"); err != errNotConfigured {
		t.Fatalf("Get = %v, want errNotConfigured (fail closed, no credential)", err)
	}
}

func TestRoutingStoreMappingShadowsMemoryValue(t *testing.T) {
	mem := NewMemoryStore(8, 64)
	if _, _, err := mem.PutIfAbsent(context.Background(), "/m", []byte("stale"), OriginWorkload); err != nil {
		t.Fatal(err)
	}
	backend := NewExternalBackend(map[string]AzureMapping{"/m": {Vault: "https://v.vault.azure.net", Name: "s"}}, nil, 64)
	s := &RoutingStore{Mem: mem, External: backend}

	st := backend.Status(mem)
	if len(st.Shadowed) != 1 || st.Shadowed[0] != "/m" {
		t.Fatalf("shadowed = %v, want [/m]", st.Shadowed)
	}
	if st.Configured {
		t.Fatal("configured = true with no credential")
	}
	// Unmap: the memory value resurfaces.
	if err := backend.Clear(); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), "/m")
	if err != nil || string(got) != "stale" {
		t.Fatalf("after unmap Get = %q, %v", got, err)
	}
}

// --- document validation ---

func validDoc() *ExternalDocument {
	return &ExternalDocument{
		Schema:     externalSchema,
		Backend:    BackendAzureKeyVault,
		Credential: AzureCredential{TenantID: "t", ClientID: "c", ClientSecret: "s"},
		Mappings:   map[string]AzureMapping{"/a": {Vault: "https://v.vault.azure.net", Name: "s1"}},
	}
}

func TestValidateExternalDocument(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ExternalDocument)
		want string
	}{
		{"ok", func(d *ExternalDocument) {}, ""},
		{"unknown backend", func(d *ExternalDocument) { d.Backend = "vault" }, "unknown backend"},
		{"schema", func(d *ExternalDocument) { d.Schema = "v2" }, "unknown schema"},
		{"non-canonical path", func(d *ExternalDocument) {
			d.Mappings = map[string]AzureMapping{"a/rel": {Vault: "https://v.vault.azure.net", Name: "s"}}
		}, "absolute"},
		{"trailing slash path", func(d *ExternalDocument) {
			d.Mappings = map[string]AzureMapping{"/a/": {Vault: "https://v.vault.azure.net", Name: "s"}}
		}, "trailing slash"},
		{"percent path", func(d *ExternalDocument) {
			d.Mappings = map[string]AzureMapping{"/a%2Fb": {Vault: "https://v.vault.azure.net", Name: "s"}}
		}, "percent"},
		{"http vault", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "http://v.vault.azure.net", Name: "s"}
		}, "bare https"},
		{"non-vault host", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://evil.example.com", Name: "s"}
		}, ".vault.azure.net"},
		{"lookalike host", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://vault.azure.net.evil.example", Name: "s"}
		}, ".vault.azure.net"},
		{"explicit port refused", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://v.vault.azure.net:443", Name: "s"}
		}, ".vault.azure.net"},
		{"empty label", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://.vault.azure.net", Name: "s"}
		}, ".vault.azure.net"},
		{"trailing question mark", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://v.vault.azure.net?", Name: "s"}
		}, "bare https"},
		{"trailing fragment", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://v.vault.azure.net#", Name: "s"}
		}, "bare https"},
		{"multi-label host", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://a.b.vault.azure.net", Name: "s"}
		}, ".vault.azure.net"},
		{"vault with userinfo", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://u:p@v.vault.azure.net", Name: "s"}
		}, "bare https"},
		{"vault with path", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://v.vault.azure.net/x", Name: "s"}
		}, "bare https"},
		{"bad secret name", func(d *ExternalDocument) {
			d.Mappings["/a"] = AzureMapping{Vault: "https://v.vault.azure.net", Name: "has space"}
		}, "must match"},
		{"tenant with slash", func(d *ExternalDocument) { d.Credential.TenantID = "a/b" }, "tenantId"},
		{"mappings without credential", func(d *ExternalDocument) { d.Credential = AzureCredential{} }, "credential requires"},
		{"credential without mappings", func(d *ExternalDocument) { d.Mappings = nil }, "credential without mappings"},
		{"empty document", func(d *ExternalDocument) {
			d.Credential = AzureCredential{}
			d.Mappings = nil
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := validDoc()
			tc.mut(doc)
			err := validateExternalDocument(doc)
			if tc.want == "" && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// --- config handler ---

func externalHandler(backend *ExternalBackend, mem *MemoryStore) ExternalConfigHandler {
	return ExternalConfigHandler{
		Backend:   backend,
		Mem:       mem,
		Authorize: func(*http.Request, []byte) error { return nil },
	}
}

func TestExternalConfigHandlerRequiresAuthorization(t *testing.T) {
	h := ExternalConfigHandler{Backend: NewExternalBackend(nil, nil, 64), Mem: NewMemoryStore(8, 64)}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestExternalConfigApplyStatusClearRoundTrip(t *testing.T) {
	backend := NewExternalBackend(nil, nil, 64)
	h := externalHandler(backend, NewMemoryStore(8, 64))

	doc := `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},"mappings":{"/a":{"vault":"https://v.vault.azure.net","name":"s1"}}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(doc)))
	if w.Code != http.StatusOK {
		t.Fatalf("apply status = %d: %s", w.Code, w.Body)
	}
	if !backend.Mapped("/a") {
		t.Fatal("mapping not live after apply")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, ExternalRoute, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var st ExternalStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Configured || st.Mappings["/a"].Name != "s1" {
		t.Fatalf("status = %+v", st)
	}
	if strings.Contains(w.Body.String(), "clientSecret") {
		t.Fatal("status leaked the credential field")
	}

	// Empty document clears.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(`{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{},"mappings":{}}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("clear status = %d: %s", w.Code, w.Body)
	}
	if backend.Mapped("/a") {
		t.Fatal("mapping survived clear")
	}
}

func TestExternalConfigRejectsInvalidDocument(t *testing.T) {
	backend := NewExternalBackend(nil, nil, 64)
	h := externalHandler(backend, NewMemoryStore(8, 64))
	doc := `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},"mappings":{"/a":{"vault":"http://insecure.vault.azure.net","name":"s1"}}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(doc)))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if backend.Mapped("/a") {
		t.Fatal("invalid document changed the backend")
	}
}

// --- persistence ---

func TestExternalMappingsPersistenceRoundTrip(t *testing.T) {
	db := filepath.Join(t.TempDir(), "allowlist.db")
	loaded, persist, err := LoadExternalMappings(db)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != nil {
		t.Fatalf("loaded = %v, want nil for a fresh store", loaded)
	}
	m := map[string]AzureMapping{"/a": {Vault: "https://v.vault.azure.net", Name: "s1"}}
	if err := persist(m); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = LoadExternalMappings(db)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["/a"].Name != "s1" {
		t.Fatalf("loaded = %v", loaded)
	}
}

func TestExternalMappingsCorruptFileFailsLoud(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "allowlist.db")
	if err := os.WriteFile(filepath.Join(dir, externalMappingsFile), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadExternalMappings(db); err == nil {
		t.Fatal("corrupt mappings file must fail startup, not silently un-back paths")
	}
}

// Duplicate mapping keys must be rejected, not last-wins.
func TestExternalConfigRejectsDuplicateMappingKeys(t *testing.T) {
	backend := NewExternalBackend(nil, nil, 64)
	h := externalHandler(backend, NewMemoryStore(8, 64))
	doc := `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},"mappings":{"/a":{"vault":"https://v.vault.azure.net","name":"s1"},"/a":{"vault":"https://w.vault.azure.net","name":"s2"}}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(doc)))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if backend.Mapped("/a") {
		t.Fatal("a duplicate-keyed document changed the backend")
	}
}

// Authorization runs before the body is parsed: a malformed document with no
// token is a 401, never a 422.
func TestExternalConfigAuthPrecedesParse(t *testing.T) {
	h := ExternalConfigHandler{Backend: NewExternalBackend(nil, nil, 64), Mem: NewMemoryStore(8, 64)}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader("not json")))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// The body cap applies to the azure route.
func TestExternalConfigBodyCap(t *testing.T) {
	h := ExternalConfigHandler{
		Backend: NewExternalBackend(nil, nil, 64), Mem: NewMemoryStore(8, 64),
		Authorize: func(*http.Request, []byte) error { return nil }, MaxBodyBytes: 8,
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(strings.Repeat("x", 64))))
	if w.Code == http.StatusOK || w.Code == http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want a body-cap refusal", w.Code)
	}
}

// A persist failure refuses the apply and leaves the backend untouched.
func TestExternalBackendApplyRefusedWhenPersistFails(t *testing.T) {
	fail := func(map[string]AzureMapping) error { return errors.New("disk full") }
	backend := NewExternalBackend(nil, fail, 64)
	err := backend.Apply(testCred, map[string]AzureMapping{"/a": {Vault: "https://v.vault.azure.net", Name: "s"}})
	if err == nil {
		t.Fatal("apply must fail when persist fails")
	}
	if backend.Mapped("/a") {
		t.Fatal("a refused apply changed the mapping set")
	}
	if err := backend.Clear(); err == nil {
		t.Fatal("clear must fail when persist fails")
	}
}

// A transport error must not carry the request URL — query string included —
// into logs or status.
func TestAzureTransportErrorStripsURL(t *testing.T) {
	c := newAzureConfig(testCred, map[string]AzureMapping{"/a": {Vault: "https://unreachable.vault.azure.net", Name: "topsecret-name"}})
	c.loginURL = "https://unreachable.login.example"
	c.client = &http.Client{Timeout: time.Second}
	_, err := c.fetch(context.Background(), "/a")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "topsecret-name") || strings.Contains(err.Error(), "api-version") {
		t.Fatalf("error leaks the request URL: %v", err)
	}
}

// The validate-then-construct pipeline produces exactly the Azure URL shape.
func TestAzureFetchURLShape(t *testing.T) {
	doc, err := parseExternalDocument([]byte(`{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t-id","clientId":"c","clientSecret":"s"},"mappings":{"/a":{"vault":"https://v.vault.azure.net/","name":"my-key"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	m := doc.Mappings["/a"]
	if m.Vault != "https://v.vault.azure.net" {
		t.Fatalf("vault not normalized: %q", m.Vault)
	}
	want := "https://v.vault.azure.net/secrets/my-key?api-version=" + azureAPIVersion
	got := m.Vault + "/secrets/" + m.Name + "?api-version=" + azureAPIVersion
	if got != want {
		t.Fatalf("fetch URL = %q, want %q", got, want)
	}
}

// Trailing data after the document is rejected.
func TestParseExternalDocumentRejectsTrailingData(t *testing.T) {
	doc := `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},"mappings":{}} trailing`
	if _, err := parseExternalDocument([]byte(doc)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

// An empty allowlist DB path disables persistence instead of writing to the
// process working directory.
func TestLoadExternalMappingsEmptyPathDisablesPersistence(t *testing.T) {
	m, persist, err := LoadExternalMappings("")
	if err != nil {
		t.Fatal(err)
	}
	if m != nil || persist != nil {
		t.Fatal("an empty DB path must disable persistence")
	}
}
