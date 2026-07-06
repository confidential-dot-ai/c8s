package allowlist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	digA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// coreImages names every default-required component so an allowlist built from
// it passes the core-component gate.
func coreImages() map[string]string {
	m := map[string]string{}
	digits := "0123456789abcdef"
	for i, comp := range defaultRequiredComponents {
		// distinct valid digests per component
		d := "sha256:" + string(digits[i]) + "000000000000000000000000000000000000000000000000000000000000000"
		m[d] = "registry.example.com/c8s/" + comp + "@" + d
	}
	return m
}

func writeAllowlistFile(t *testing.T, dir string, digests map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "allowlist.json")
	data, err := json.Marshal(map[string]any{"version": "1", "digests": digests})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// writeOperatorKey writes an EC private key PEM to dir and returns its path.
func writeOperatorKey(t *testing.T, dir string) (keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	keyPath = filepath.Join(dir, "op.key")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath
}

// recordingCDS is an httptest server that records the HTTP methods it saw and
// serves an empty allowlist on GET.
func recordingCDS(t *testing.T) (url string, methods *[]string) {
	t.Helper()
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(types.AllowlistListResponse{Version: "1", Digests: map[types.Digest]string{}})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

func runCmd(args ...string) (string, string, error) {
	cmd := NewCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func contains(methods []string, m string) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

// --- pure helpers ---

func TestMissingComponents(t *testing.T) {
	full := coreImages()
	if got := missingComponents(full, defaultRequiredComponents); len(got) != 0 {
		t.Fatalf("expected no missing components, got %v", got)
	}

	partial := map[string]string{digA: "registry/c8s/cds@" + digA}
	got := missingComponents(partial, defaultRequiredComponents)
	if len(got) != len(defaultRequiredComponents)-1 {
		t.Fatalf("expected all but cds missing, got %v", got)
	}
	for _, c := range got {
		if c == "cds" {
			t.Fatal("cds should not be reported missing")
		}
	}
}

// TestMissingComponentsMatchesRealChartImages pins the defaultRequiredComponents
// substring needles against the actual chart image repositories, so a rename
// (notably the tls-lb "nginxinc/nginx-unprivileged" image, which only matches
// the "nginx" needle as a substring) can't silently defeat the upload guard.
func TestMissingComponentsMatchesRealChartImages(t *testing.T) {
	chartImages := map[string]string{
		"a": "ghcr.io/confidential-dot-ai/cds@sha256:1",
		"b": "ghcr.io/confidential-dot-ai/ratls-mesh@sha256:2",
		"c": "ghcr.io/confidential-dot-ai/nri-image-policy@sha256:3",
		"d": "ghcr.io/confidential-dot-ai/attestation-api@sha256:4",
		"e": "nginxinc/nginx-unprivileged@sha256:5",
	}
	if got := missingComponents(chartImages, defaultRequiredComponents); len(got) != 0 {
		t.Fatalf("real chart images should satisfy every required component, missing: %v", got)
	}

	// Sanity: dropping the tls-lb image reports exactly "nginx" — proving that
	// entry is really carried by nginxinc/nginx-unprivileged and nothing else.
	delete(chartImages, "e")
	got := missingComponents(chartImages, defaultRequiredComponents)
	if len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("dropping the nginx image should report exactly [nginx], got %v", got)
	}
}

func TestComputeDiff(t *testing.T) {
	current := map[string]string{digA: "img-a", digB: "img-b-old"}
	desired := map[string]string{digB: "img-b-new", "sha256:" + repeat("c", 64): "img-c"}

	d := computeDiff(current, desired)
	if len(d.Added) != 1 || d.Added["sha256:"+repeat("c", 64)] != "img-c" {
		t.Fatalf("added wrong: %#v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[digA] != "img-a" {
		t.Fatalf("removed wrong: %#v", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[digB].From != "img-b-old" || d.Changed[digB].To != "img-b-new" {
		t.Fatalf("changed wrong: %#v", d.Changed)
	}
}

// --- command behavior ---

func TestUploadRefusesMissingCoreWithoutForce(t *testing.T) {
	dir := t.TempDir()
	file := writeAllowlistFile(t, dir, map[string]string{digA: "registry/app/only@" + digA})

	_, _, err := runCmd("upload", file, "--url", "https://cds.example:8443")
	if err == nil {
		t.Fatal("expected upload to refuse a file missing core components")
	}
}

func TestUploadForceProceedsInDryRun(t *testing.T) {
	dir := t.TempDir()
	// Missing core components, but --force + --dry-run: should not error and not write.
	file := writeAllowlistFile(t, dir, map[string]string{digA: "registry/app/only@" + digA})
	url, methods := recordingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--force", "--dry-run")
	if err != nil {
		t.Fatalf("force+dry-run should succeed, got %v", err)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("dry-run must not issue a PUT")
	}
}

func TestUploadReplacesWhenCoreComplete(t *testing.T) {
	dir := t.TempDir()
	file := writeAllowlistFile(t, dir, coreImages())
	keyPath := writeOperatorKey(t, dir)
	url, methods := recordingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
}

func TestHTTPRefusedWithoutInsecure(t *testing.T) {
	url, methods := recordingCDS(t) // http:// httptest endpoint
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)

	_, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--operator-key", keyPath)
	if err == nil {
		t.Fatal("expected a plaintext http:// CDS URL to be refused without --insecure")
	}
	if contains(*methods, http.MethodPost) {
		t.Fatal("must not connect to a plaintext endpoint when --insecure is absent")
	}
}

func TestAddDryRunMakesNoCall(t *testing.T) {
	url, methods := recordingCDS(t)
	_, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--dry-run")
	if err != nil {
		t.Fatalf("add --dry-run failed: %v", err)
	}
	if contains(*methods, http.MethodPost) {
		t.Fatal("dry-run must not issue a POST")
	}
}

func TestWriteRequiresOperatorCredential(t *testing.T) {
	url, _ := recordingCDS(t)
	// No key and no env: a real (non-dry-run) add must fail before writing.
	t.Setenv(envOperatorKey, "")
	_, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url)
	if err == nil {
		t.Fatal("expected add without an operator key to fail")
	}
}

func TestSignerPrefersFlagOverEnv(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	t.Setenv(envOperatorKey, filepath.Join(dir, "nonexistent.key"))

	o := &options{operatorKey: keyPath}
	if _, err := o.signer(); err != nil {
		t.Fatalf("flag should take precedence over (broken) env, got %v", err)
	}
}

func TestSignerFallsBackToEnv(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	t.Setenv(envOperatorKey, keyPath)

	o := &options{} // no flags
	if _, err := o.signer(); err != nil {
		t.Fatalf("env fallback should work, got %v", err)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s[0])
	}
	return string(out)
}

// guard against accidental duplicate flag registration panics.
func TestNewCmdWiring(t *testing.T) {
	cmd := NewCmd()
	want := []string{"list", "export", "diff", "add", "remove", "upload"}
	for _, name := range want {
		found := false
		for _, c := range cmd.Commands() {
			if c.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
	_ = fmt.Sprint(cmd.Use)
}
