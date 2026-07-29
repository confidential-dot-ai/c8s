package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
)

// fakeCDS serves PUT /secrets/* with the create-safe semantics the real handler
// has, recording each request so a test can assert on what the CLI sent.
type fakeCDS struct {
	mu      sync.Mutex
	values  map[string]intsecrets.Origin
	seen    []intsecrets.PutRequest
	authz   []string
	paths   []string
	failAll bool
}

func newFakeCDS(t *testing.T) (*fakeCDS, string) {
	t.Helper()
	f := &fakeCDS{values: map[string]intsecrets.Origin{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func (f *fakeCDS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll {
		http.Error(w, "nope", http.StatusInternalServerError)
		return
	}
	var req intsecrets.PutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/secrets")
	f.seen = append(f.seen, req)
	f.authz = append(f.authz, r.Header.Get("Authorization"))
	f.paths = append(f.paths, r.URL.Path)

	existing, held := f.values[path]
	resp := intsecrets.PutResponse{Path: path}
	status := http.StatusCreated
	switch {
	case !held:
		f.values[path] = intsecrets.OriginOperator
		resp.Created = true
	case !req.Overwrite:
		status = http.StatusConflict
		resp.Existing = existing
	default:
		f.values[path] = intsecrets.OriginOperator
		status = http.StatusOK
		resp.Existing = existing
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeCDS) seed(path string, by intsecrets.Origin) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[path] = by
}

func writeOperatorKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "operator.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// run drives the command tree the way a shell would, with stdin supplied.
func run(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newCmd(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		return nil, nil
	})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func TestPutCreates(t *testing.T) {
	f, url := newFakeCDS(t)
	key := writeOperatorKey(t)

	out, _, err := run(t, "hunter2", "put", "/tenant-a/db", "--url", url, "--insecure", "--operator-key", key)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !strings.Contains(out, "+ /tenant-a/db (new)") || !strings.Contains(out, "wrote 7 bytes to /tenant-a/db") {
		t.Fatalf("output = %q", out)
	}
	if len(f.seen) != 1 {
		t.Fatalf("sent %d requests, want 1", len(f.seen))
	}
	if f.seen[0].Overwrite {
		t.Fatal("a plain put carried overwrite intent")
	}
	if got, _ := base64.StdEncoding.DecodeString(f.seen[0].Value); string(got) != "hunter2" {
		t.Fatalf("value = %q", got)
	}
	if f.paths[0] != "/secrets/tenant-a/db" {
		t.Fatalf("path = %q", f.paths[0])
	}
	if !strings.HasPrefix(f.authz[0], "Bearer ") {
		t.Fatalf("Authorization = %q, want an operator bearer token", f.authz[0])
	}
}

// The refusal names what is there and leaves it alone, which is the whole point
// of asking to create before asking to replace.
func TestPutRefusesOccupiedPathWithoutOverwrite(t *testing.T) {
	f, url := newFakeCDS(t)
	f.seed("/tenant-a/db", intsecrets.OriginWorkload)
	key := writeOperatorKey(t)

	out, _, err := run(t, "hunter2", "put", "/tenant-a/db", "--url", url, "--insecure", "--operator-key", key)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "a workload-generated value") || !strings.Contains(err.Error(), "--overwrite") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(out, "wrote") {
		t.Fatalf("the refusal claimed to have written: %q", out)
	}
	if len(f.seen) != 1 || f.seen[0].Overwrite {
		t.Fatalf("sent %+v, want a single create attempt", f.seen)
	}
}

// --overwrite still asks to create first, so the line naming what is destroyed
// is printed before the write that destroys it.
func TestPutOverwriteNamesWhatItReplaces(t *testing.T) {
	f, url := newFakeCDS(t)
	f.seed("/tenant-a/db", intsecrets.OriginWorkload)
	key := writeOperatorKey(t)

	out, errOut, err := run(t, "hunter2", "put", "/tenant-a/db", "--url", url, "--insecure", "--operator-key", key, "--overwrite")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !strings.Contains(out, "~ /tenant-a/db (replaces a workload-generated value)") {
		t.Fatalf("output = %q", out)
	}
	if idx, wrote := strings.Index(out, "~ /tenant-a/db"), strings.Index(out, "wrote 7 bytes"); idx < 0 || wrote < idx {
		t.Fatalf("the replacement line did not precede the write: %q", out)
	}
	if !strings.Contains(errOut, "keep it until they restart") {
		t.Fatalf("stderr = %q, want the restart note", errOut)
	}
	if len(f.seen) != 2 || f.seen[0].Overwrite || !f.seen[1].Overwrite {
		t.Fatalf("sent %+v, want a create attempt then an overwrite", f.seen)
	}
}

// Replacing an operator value is routine rotation, so it says so rather than
// warning about pods that generated it.
func TestPutOverwriteOfOperatorValue(t *testing.T) {
	f, url := newFakeCDS(t)
	f.seed("/tenant-a/db", intsecrets.OriginOperator)
	key := writeOperatorKey(t)

	out, errOut, err := run(t, "v2", "put", "/tenant-a/db", "--url", url, "--insecure", "--operator-key", key, "--overwrite")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !strings.Contains(out, "replaces an operator-supplied value") {
		t.Fatalf("output = %q", out)
	}
	if strings.Contains(errOut, "keep it until they restart") {
		t.Fatalf("stderr warned about a workload value it did not replace: %q", errOut)
	}
}

// --overwrite onto an empty path is a creation and reports as one.
func TestPutOverwriteOnEmptyPath(t *testing.T) {
	f, url := newFakeCDS(t)
	key := writeOperatorKey(t)

	out, _, err := run(t, "v", "put", "/a", "--url", url, "--insecure", "--operator-key", key, "--overwrite")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !strings.Contains(out, "+ /a (new)") {
		t.Fatalf("output = %q", out)
	}
	if len(f.seen) != 1 {
		t.Fatalf("sent %d requests, want 1", len(f.seen))
	}
}

func TestPutFromFile(t *testing.T) {
	f, url := newFakeCDS(t)
	key := writeOperatorKey(t)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("hf_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := run(t, "", "put", "/a", "--url", url, "--insecure", "--operator-key", key, "--from-file", path); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, _ := base64.StdEncoding.DecodeString(f.seen[0].Value)
	if string(got) != "hf_abc\n" {
		t.Fatalf("value = %q, want the file's bytes unmodified including the newline", got)
	}
}

func TestPutDryRunDoesNotCallCDS(t *testing.T) {
	f, url := newFakeCDS(t)
	key := writeOperatorKey(t)

	out, _, err := run(t, "hunter2", "put", "/a", "--url", url, "--insecure", "--operator-key", key, "--dry-run")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !strings.Contains(out, "would write 7 bytes to /a") {
		t.Fatalf("output = %q", out)
	}
	if len(f.seen) != 0 {
		t.Fatal("--dry-run reached CDS")
	}
}

func TestPutRejectsBadInput(t *testing.T) {
	_, url := newFakeCDS(t)
	key := writeOperatorKey(t)
	base := []string{"--url", url, "--insecure", "--operator-key", key}

	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"relative path", "v", []string{"put", "tenant/db"}, "must be absolute"},
		{"wildcard path", "v", []string{"put", "/tenant/**"}, "must not contain wildcards"},
		{"uncanonical path", "v", []string{"put", "/tenant/../db"}, "not clean"},
		{"empty stdin", "", []string{"put", "/a"}, "value is empty"},
		{"missing file", "", []string{"put", "/a", "--from-file", "/nope/nothing"}, "read --from-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := run(t, tc.stdin, append(tc.args, base...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A URL with no attestation must be refused unless the operator asked for it.
func TestPutRefusesPlaintextWithoutInsecure(t *testing.T) {
	_, url := newFakeCDS(t)
	key := writeOperatorKey(t)
	_, _, err := run(t, "v", "put", "/a", "--url", url, "--operator-key", key)
	if err == nil || !strings.Contains(err.Error(), "refusing plaintext") {
		t.Fatalf("err = %v", err)
	}
}

func TestPutRequiresURLAndKey(t *testing.T) {
	t.Setenv("C8S_OPERATOR_KEY", "")
	if _, _, err := run(t, "v", "put", "/a"); err == nil || !strings.Contains(err.Error(), "--url is required") {
		t.Fatalf("err = %v, want a --url error", err)
	}
	_, url := newFakeCDS(t)
	if _, _, err := run(t, "v", "put", "/a", "--url", url, "--insecure"); err == nil ||
		!strings.Contains(err.Error(), "operator key required") {
		t.Fatalf("err = %v, want an operator-key error", err)
	}
}

func TestPutSurfacesServerErrors(t *testing.T) {
	f, url := newFakeCDS(t)
	f.failAll = true
	key := writeOperatorKey(t)
	_, _, err := run(t, "v", "put", "/a", "--url", url, "--insecure", "--operator-key", key)
	if err == nil || !strings.Contains(err.Error(), "cds returned 500") {
		t.Fatalf("err = %v", err)
	}
}
