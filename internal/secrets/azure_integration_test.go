package secrets

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// azureHarness wires the workload handler to a RoutingStore whose Azure
// backend talks to a fake vault.
func azureHarness(t *testing.T, f *fakeAzure, withCredential bool) (*harness, *ExternalBackend) {
	t.Helper()
	hn := newHarness(t)
	backend := NewExternalBackend(nil, nil, 64)
	if withCredential {
		backend.mu.Lock()
		backend.mapped = map[string]AzureMapping{"/api/key": {Vault: f.srv.URL, Name: "s1"}}
		backend.live = f.config(testCred, backend.mapped)
		backend.mu.Unlock()
	} else {
		backend.mu.Lock()
		backend.mapped = map[string]AzureMapping{"/api/key": {Vault: f.srv.URL, Name: "s1"}}
		backend.mu.Unlock()
	}
	hn.h.Store = &RoutingStore{Mem: hn.store, External: backend}
	return hn, backend
}

func TestWorkloadGetMappedPathFetchesFromVault(t *testing.T) {
	f := newFakeAzure(t)
	hn, _ := azureHarness(t, f, true)
	w := do(hn.h, hn.request(t, http.MethodGet, "/api/key"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	if got := decodeValue(t, w); got != base64.StdEncoding.EncodeToString([]byte("vault-value")) {
		t.Fatalf("value = %q", got)
	}
}

func TestWorkloadGetMappedPathFailsClosedWithoutCredential(t *testing.T) {
	f := newFakeAzure(t)
	hn, _ := azureHarness(t, f, false)
	w := do(hn.h, hn.request(t, http.MethodGet, "/api/key"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fail closed)", w.Code)
	}
	if got := f.secretCalls.Load(); got != 0 {
		t.Fatalf("vault calls = %d, want 0 without a credential", got)
	}
}

// A POST on a mapped path must not mint: 409, and the vault value is what a
// following GET reads.
func TestWorkloadPostMappedPathDoesNotMint(t *testing.T) {
	f := newFakeAzure(t)
	hn, _ := azureHarness(t, f, true)
	w := do(hn.h, hn.request(t, http.MethodPost, "/api/key"))
	if w.Code != http.StatusConflict {
		t.Fatalf("POST status = %d, want 409", w.Code)
	}
	if _, err := hn.store.Get(t.Context(), "/api/key"); err != ErrNotFound {
		t.Fatal("the refused POST minted a value into the memory store")
	}
	w = do(hn.h, hn.request(t, http.MethodGet, "/api/key"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET after POST status = %d", w.Code)
	}
	if got := decodeValue(t, w); got != base64.StdEncoding.EncodeToString([]byte("vault-value")) {
		t.Fatalf("value = %q, want the vault value", got)
	}
}

// The review's regression test: an operator write to a mapped path is a
// refusal on BOTH the create and the overwrite path — never a false success.
func TestOperatorPutMappedPathRefusedOnCreateAndOverwrite(t *testing.T) {
	backend := NewExternalBackend(map[string]AzureMapping{"/api/key": {Vault: "https://v.vault.azure.net", Name: "s1"}}, nil, 64)
	mem := NewMemoryStore(16, 64)
	h := OperatorHandler{
		Store:     &RoutingStore{Mem: mem, External: backend},
		Authorize: func(*http.Request, []byte) error { return nil },
	}
	for _, overwrite := range []bool{false, true} {
		body, _ := json.Marshal(PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("x")), Overwrite: overwrite})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/secrets/api/key", strings.NewReader(string(body))))
		if w.Code != http.StatusConflict {
			t.Fatalf("overwrite=%v: status = %d, want 409 (a refusal, not a silent no-op)", overwrite, w.Code)
		}
		var resp PutResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Existing != OriginExternal {
			t.Fatalf("overwrite=%v: existing = %q, want %q", overwrite, resp.Existing, OriginExternal)
		}
	}
	if _, err := mem.Get(t.Context(), "/api/key"); err != ErrNotFound {
		t.Fatal("a refused write landed in the memory store")
	}
}

// Unmapped paths are untouched by the backend.
func TestOperatorPutUnmappedPathStillWorks(t *testing.T) {
	backend := NewExternalBackend(nil, nil, 64)
	mem := NewMemoryStore(16, 64)
	h := OperatorHandler{
		Store:     &RoutingStore{Mem: mem, External: backend},
		Authorize: func(*http.Request, []byte) error { return nil },
	}
	body, _ := json.Marshal(PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("x"))})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/secrets/api/db", strings.NewReader(string(body))))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
}
