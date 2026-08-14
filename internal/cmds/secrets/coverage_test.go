package secrets

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
)

// --- readExternalDoc ---

func TestReadExternalDocMissingFile(t *testing.T) {
	cmd := newExternalApplyCmd(&options{})
	if _, err := readExternalDoc(cmd, filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestReadExternalDocEmpty(t *testing.T) {
	cmd := newExternalApplyCmd(&options{})
	cmd.SetIn(strings.NewReader("  \n"))
	if _, err := readExternalDoc(cmd, ""); err == nil {
		t.Fatal("empty stdin must fail")
	}
}

func TestReadExternalDocFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(path, []byte(`{"schema":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newExternalApplyCmd(&options{})
	got, err := readExternalDoc(cmd, path)
	if err != nil || !strings.Contains(string(got), "schema") {
		t.Fatalf("got %q, %v", got, err)
	}
}

// --- printExternalStatus branches ---

func TestPrintExternalStatusBranches(t *testing.T) {
	var buf bytes.Buffer

	printExternalStatus(&buf, intsecrets.ExternalStatus{})
	if !strings.Contains(buf.String(), "backend is off") {
		t.Fatalf("empty: %q", buf.String())
	}

	buf.Reset()
	printExternalStatus(&buf, intsecrets.ExternalStatus{
		Mappings: map[string]intsecrets.AzureMapping{"/a": {Vault: "https://v.vault.azure.net", Name: "s"}},
	})
	if !strings.Contains(buf.String(), "NO CREDENTIAL") {
		t.Fatalf("unconfigured: %q", buf.String())
	}

	buf.Reset()
	printExternalStatus(&buf, intsecrets.ExternalStatus{
		Configured: true,
		Mappings:   map[string]intsecrets.AzureMapping{"/a": {Vault: "https://v.vault.azure.net", Name: "s"}},
		LastFetch: map[string]intsecrets.FetchRecord{
			"/a": {Err: "secrets: vault answered 500"},
			"/b": {},
		},
		Shadowed: []string{"/a"},
	})
	out := buf.String()
	for _, want := range []string{"credential applied", "last fetch FAILED", "shadows"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}

// --- doExternal error paths ---

func TestDoExternalServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	keyPath := writeOperatorKey(t)
	if _, _, err := run(t, "", "external", "status", "--url", srv.URL, "--insecure", "--operator-key", keyPath); err == nil {
		t.Fatal("a CDS error must surface")
	}
}

func TestDoExternalBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)
	keyPath := writeOperatorKey(t)
	_, _, err := run(t, "", "external", "status", "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v, want a decode failure", err)
	}
}

// --- apply: empty stdin refuses before calling CDS ---

func TestExternalApplyEmptyDoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("CDS called with an empty document")
	}))
	t.Cleanup(srv.Close)
	keyPath := writeOperatorKey(t)
	if _, _, err := run(t, "", "external", "apply", "--url", srv.URL, "--insecure", "--operator-key", keyPath); err == nil {
		t.Fatal("empty document must fail before any call")
	}
}

// --- status --json ---

func TestExternalStatusJSON(t *testing.T) {
	f, url := newFakeExternalCDS(t)
	f.status = intsecrets.ExternalStatus{Configured: true, Mappings: map[string]intsecrets.AzureMapping{
		"/a": {Vault: "https://v.vault.azure.net", Name: "s"},
	}}
	keyPath := writeOperatorKey(t)
	out, _, err := run(t, "", "external", "status", "--json", "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var st intsecrets.ExternalStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("--json output does not decode: %v", err)
	}
}

// --- describe ---

func TestDescribeOrigins(t *testing.T) {
	if got := describe(intsecrets.Origin("mystery")); got != "a value" {
		t.Fatalf("describe(default) = %q", got)
	}
	if got := describe(intsecrets.OriginExternal); !strings.Contains(got, "external") {
		t.Fatalf("describe(external) = %q", got)
	}
}
