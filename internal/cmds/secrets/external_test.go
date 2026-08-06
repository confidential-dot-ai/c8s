package secrets

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
)

// fakeExternalCDS serves PUT/GET on the azure config route, recording what the
// CLI sent.
type fakeExternalCDS struct {
	mu     sync.Mutex
	status intsecrets.ExternalStatus
	seen   []string // raw bodies
	authz  []string
}

func newFakeExternalCDS(t *testing.T) (*fakeExternalCDS, string) {
	t.Helper()
	f := &fakeExternalCDS{status: intsecrets.ExternalStatus{Mappings: map[string]intsecrets.AzureMapping{}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path != intsecrets.ExternalRoute {
			http.NotFound(w, r)
			return
		}
		f.authz = append(f.authz, r.Header.Get("Authorization"))
		switch r.Method {
		case http.MethodPut:
			buf, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.seen = append(f.seen, string(buf))
			var doc struct {
				Mappings map[string]intsecrets.AzureMapping `json:"mappings"`
			}
			if err := json.Unmarshal(buf, &doc); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			f.status = intsecrets.ExternalStatus{Configured: len(doc.Mappings) > 0, Mappings: doc.Mappings}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.status)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.status)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv.URL
}

const testAzureDoc = `{"schema":"c8s.secrets-external/v1","backend":"azure-keyvault","credential":{"tenantId":"t","clientId":"c","clientSecret":"s"},"mappings":{"/a":{"vault":"https://v.vault.azure.net","name":"s1"}}}`

func TestExternalApplySendsTheDocument(t *testing.T) {
	f, url := newFakeExternalCDS(t)
	keyPath := writeOperatorKey(t)
	out, _, err := run(t, testAzureDoc, "external", "apply", "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.seen) != 1 || !strings.Contains(f.seen[0], `"clientSecret":"s"`) {
		t.Fatalf("the document did not reach CDS: %v", f.seen)
	}
	if len(f.authz) != 1 || !strings.HasPrefix(f.authz[0], "Bearer ") {
		t.Fatalf("no operator token on the write: %v", f.authz)
	}
	if !strings.Contains(out, "/a -> https://v.vault.azure.net/secrets/s1") {
		t.Fatalf("status output missing the mapping: %q", out)
	}
}

func TestExternalStatusHidesNothingButTheSecret(t *testing.T) {
	_, url := newFakeExternalCDS(t)
	keyPath := writeOperatorKey(t)
	if _, _, err := run(t, testAzureDoc, "external", "apply", "--url", url, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, "", "external", "status", "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "credential applied") {
		t.Fatalf("status output: %q", out)
	}
	if strings.Contains(out, `"s"`) || strings.Contains(out, "clientSecret") {
		t.Fatalf("status leaked the credential: %q", out)
	}
}
