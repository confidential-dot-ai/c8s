package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// End-to-end: operator applies an external-KMS config over the authorized
// endpoint, an attested workload reads a mapped path through the release gate,
// and a simulated restart fails closed until the credential is re-applied.
// The Azure side is a stubbed Entra+vault TLS server.
func TestExternalKMSEndToEnd(t *testing.T) {
	fake := newFakeAzure(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "allowlist.db")

	// The operator keypair: the private half signs CLI requests, the public
	// half is what CDS pins.
	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opKeyDER, err := x509.MarshalPKCS8PrivateKey(opKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: opKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&opKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	keys, err := operatorauth.ParsePublicKeysPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	verifier := operatorauth.Verifier{Keys: keys}

	// CDS side: one routing store behind the workload, operator, and config
	// handlers, with real persistence.
	persisted, persist, err := LoadExternalMappings(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	backend := NewExternalBackend(persisted, persist, 64)
	backend.newConfig = func(cred AzureCredential, mappings map[string]AzureMapping) *azureConfig {
		remapped := map[string]AzureMapping{}
		for p := range mappings {
			remapped[p] = AzureMapping{Vault: fake.srv.URL, Name: mappings[p].Name}
		}
		return fake.config(cred, remapped)
	}
	mem := NewMemoryStore(16, 64)
	store := &RoutingStore{Mem: mem, External: backend}

	hn := newHarness(t)
	hn.h.Store = store
	configH := ExternalConfigHandler{Backend: backend, Mem: mem, Authorize: verifier.Authorize}
	operatorH := OperatorHandler{Store: store, Authorize: verifier.Authorize}

	// signedCall runs one operator request through the real JWT machinery.
	signedCall := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		authz, err := signer.Authorization(method, req.URL.Path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", authz)
		w := httptest.NewRecorder()
		configH.ServeHTTP(w, req)
		return w
	}

	// 1. An unsigned config write is refused before anything is read.
	w := httptest.NewRecorder()
	configH.ServeHTTP(w, httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(`{"x":1}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned config write = %d, want 401", w.Code)
	}

	// 2. The operator applies the config.
	doc := `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault",` +
		`"credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},` +
		`"mappings":{"/api/key":{"vault":"https://v.vault.azure.net","name":"s1"}}}`
	if w := signedCall(http.MethodPut, ExternalRoute, []byte(doc)); w.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", w.Code, w.Body)
	}

	// 3. An attested, grant-holding workload reads the vault value.
	w = do(hn.h, hn.request(t, http.MethodGet, "/api/key"))
	if w.Code != http.StatusOK {
		t.Fatalf("workload GET = %d: %s", w.Code, w.Body)
	}
	if got := decodeValue(t, w); got != base64.StdEncoding.EncodeToString([]byte("vault-value")) {
		t.Fatalf("value = %q, want the vault value", got)
	}

	// 4. A mapped path cannot be minted by a workload...
	w = do(hn.h, hn.request(t, http.MethodPost, "/api/key"))
	if w.Code != http.StatusConflict {
		t.Fatalf("workload POST = %d, want 409", w.Code)
	}
	// ...nor written by the operator.
	putBody, _ := json.Marshal(PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("x"))})
	req := httptest.NewRequest(http.MethodPut, "/secrets/api/key", strings.NewReader(string(putBody)))
	authz, err := signer.Authorization(http.MethodPut, req.URL.Path, putBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authz)
	w = httptest.NewRecorder()
	operatorH.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("operator PUT = %d, want 409", w.Code)
	}

	// 5. The grant gate still runs first: the same workload holds no grant for
	// /other/key, so mapping or not, it is refused before any store lookup.
	w = do(hn.h, hn.request(t, http.MethodGet, "/other/key"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("ungranted GET = %d, want 404", w.Code)
	}

	// 6. Status reports the mapping and the successful fetch, never the
	// credential or the value.
	w = signedCall(http.MethodGet, ExternalRoute, nil)
	var st ExternalStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Configured || st.Mappings["/api/key"].Name != "s1" || st.LastFetch["/api/key"].Err != "" {
		t.Fatalf("status = %+v", st)
	}
	if strings.Contains(w.Body.String(), "vault-value") || strings.Contains(w.Body.String(), `"s"`) {
		t.Fatal("status leaked a secret")
	}

	// 7. Simulate a CDS restart: a new backend over the same persisted file,
	// no credential. Mapped paths fail closed — no fetch, no mint.
	restarted := NewExternalBackend(mustLoad(t, dbPath), nil, 64)
	restarted.newConfig = backend.newConfig
	hn.h.Store = &RoutingStore{Mem: mem, External: restarted}
	w = do(hn.h, hn.requestWith(t, http.MethodGet, "/api/key", hn.leaf, testSandbox, []byte("nonce-restart-get")))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("GET after restart = %d, want 500 (fail closed)", w.Code)
	}
	w = do(hn.h, hn.requestWith(t, http.MethodPost, "/api/key", hn.leaf, testSandbox, []byte("nonce-restart-post")))
	if w.Code != http.StatusConflict {
		t.Fatalf("POST after restart = %d, want 409 (no mint)", w.Code)
	}
	if _, err := mem.Get(t.Context(), "/api/key"); err != ErrNotFound {
		t.Fatal("a value was minted behind the mapping")
	}

	// 8. Re-applying the credential re-arms the mappings.
	restartedCfg := ExternalConfigHandler{Backend: restarted, Mem: mem, Authorize: verifier.Authorize}
	req = httptest.NewRequest(http.MethodPut, ExternalRoute, strings.NewReader(doc))
	authz, err = signer.Authorization(http.MethodPut, req.URL.Path, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authz)
	w = httptest.NewRecorder()
	restartedCfg.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("re-apply = %d: %s", w.Code, w.Body)
	}
	w = do(hn.h, hn.requestWith(t, http.MethodGet, "/api/key", hn.leaf, testSandbox, []byte("nonce-reapply-get")))
	if w.Code != http.StatusOK {
		t.Fatalf("GET after re-apply = %d: %s", w.Code, w.Body)
	}
}

func mustLoad(t *testing.T, dbPath string) map[string]AzureMapping {
	t.Helper()
	m, _, err := LoadExternalMappings(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) == 0 {
		t.Fatal("no persisted mappings after apply")
	}
	return m
}
