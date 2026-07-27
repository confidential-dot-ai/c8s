package allowlist

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// servingCDS is an httptest server that serves the given digests on GET (as a
// canonical allowlist document) and accepts writes with 204, recording the
// HTTP methods it saw.
func servingCDS(t *testing.T, digests map[string]string) (url string, methods *[]string) {
	t.Helper()
	doc := pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Digests:   digests,
		Workloads: map[string]pkgallowlist.Workload{},
	}
	body, err := doc.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `W/"7"`)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

// listFailingCDS fails every GET with 500 but accepts writes (recording the
// methods it saw), so the "could not fetch allowlist" warning paths run.
func listFailingCDS(t *testing.T) (url string, methods *[]string) {
	t.Helper()
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		if r.Method == http.MethodGet {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

// --- validate / client flag handling ---

func TestValidateRejectsBadOutputFormat(t *testing.T) {
	_, _, err := runCmd("list", "--url", "http://cds.example", "--insecure", "-o", "yaml")
	if err == nil || !strings.Contains(err.Error(), "--output must be text or json") {
		t.Fatalf("expected an output-format error, got %v", err)
	}
}

func TestClientRejectsInvalidURL(t *testing.T) {
	_, _, err := runCmd("list", "--url", "http://")
	if err == nil || !strings.Contains(err.Error(), "invalid --url") {
		t.Fatalf("expected an invalid --url error, got %v", err)
	}
}

func TestClientRejectsUnknownScheme(t *testing.T) {
	_, _, err := runCmd("list", "--url", "ftp://cds.example")
	if err == nil || !strings.Contains(err.Error(), "scheme must be http or https") {
		t.Fatalf("expected a scheme error, got %v", err)
	}
}

// --- loadMeasurements ---

func TestLoadMeasurementsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.txt")
	m1 := strings.Repeat("42", ratls.SNPMeasurementSize)
	m2 := strings.Repeat("ab", ratls.SNPMeasurementSize)
	// blank lines and surrounding whitespace must be tolerated
	if err := os.WriteFile(path, []byte(m1+"\n\n  "+m2+"  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	o := &options{measurementsFile: path}
	got, err := o.loadMeasurements()
	if err != nil {
		t.Fatalf("loadMeasurements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 measurements, got %d", len(got))
	}
}

func TestLoadMeasurementsCombinesFlagAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "measurements.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("ab", ratls.SNPMeasurementSize)+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	o := &options{
		measurements:     []string{strings.Repeat("42", ratls.SNPMeasurementSize)},
		measurementsFile: path,
	}
	got, err := o.loadMeasurements()
	if err != nil {
		t.Fatalf("loadMeasurements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected flag+file to combine into 2 measurements, got %d", len(got))
	}
}

func TestLoadMeasurementsFileMissing(t *testing.T) {
	o := &options{measurementsFile: filepath.Join(t.TempDir(), "nope.txt")}
	if _, err := o.loadMeasurements(); err == nil || !strings.Contains(err.Error(), "read --measurements-file") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestLoadMeasurementsRejectsBadHex(t *testing.T) {
	o := &options{measurements: []string{"not-hex"}}
	if _, err := o.loadMeasurements(); err == nil {
		t.Fatal("expected invalid hex to be rejected")
	}
}

// --- signer error paths ---

func TestSignerMissingKeyFile(t *testing.T) {
	o := &options{operatorKey: filepath.Join(t.TempDir(), "nope.key")}
	if _, err := o.signer(); err == nil || !strings.Contains(err.Error(), "read operator key") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestSignerRejectsGarbagePEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	o := &options{operatorKey: path}
	if _, err := o.signer(); err == nil || !strings.Contains(err.Error(), "load operator key") {
		t.Fatalf("expected a key-parse error, got %v", err)
	}
}

// --- list / export ---

func TestListJSONOutput(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})

	out, _, err := runCmd("list", "--url", url, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("list -o json: %v", err)
	}
	var resp pkgallowlist.Allowlist
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(resp.Digests) != 1 || resp.Digests[digA] == "" {
		t.Fatalf("unexpected response round-trip: %+v", resp)
	}
}

func TestExportToStdout(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})

	out, _, err := runCmd("export", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(out, digA) {
		t.Fatalf("exported JSON missing digest:\n%s", out)
	}

	// "-" is an explicit stdout spelling.
	dashOut, _, err := runCmd("export", "-", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("export -: %v", err)
	}
	if dashOut != out {
		t.Fatalf("export - differs from bare export:\n%s\nvs\n%s", dashOut, out)
	}
}

func TestExportToFileRoundTrips(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})
	path := filepath.Join(t.TempDir(), "backup.json")

	_, _, err := runCmd("export", path, "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("export to file: %v", err)
	}

	// The exported file must round-trip through the same loader upload/diff use.
	wl, err := loadAllowlistFile(path)
	if err != nil {
		t.Fatalf("re-load exported file: %v", err)
	}
	if wl.Digests[digA] != "registry/app@"+digA {
		t.Fatalf("round-trip lost the entry: %#v", wl.Digests)
	}
}

func TestExportWriteFailure(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})
	path := filepath.Join(t.TempDir(), "missing-dir", "backup.json")

	_, _, err := runCmd("export", path, "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("expected a write error, got %v", err)
	}
}

// --- diff ---

func TestDiffJSONOutput(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "img-a"})
	file := writeAllowlistFile(t, t.TempDir(), map[string]string{digB: "img-b"})

	out, _, err := runCmd("diff", file, "--url", url, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("diff -o json: %v", err)
	}
	var d allowlistDiff
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if d.Floor.Added[digB] != "img-b" || d.Floor.Removed[digA] != "img-a" {
		t.Fatalf("unexpected diff: %#v", d)
	}
}

func TestDiffRejectsBadFile(t *testing.T) {
	url, _ := servingCDS(t, nil)

	if _, _, err := runCmd("diff", filepath.Join(t.TempDir(), "nope.json"), "--url", url, "--insecure"); err == nil {
		t.Fatal("expected a missing allowlist file to fail")
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := runCmd("diff", bad, "--url", url, "--insecure"); err == nil || !strings.Contains(err.Error(), "parse allowlist file") {
		t.Fatalf("expected a parse error, got %v", err)
	}
}

// --- add / remove ---

func TestAddRejectsInvalidDigest(t *testing.T) {
	url, methods := recordingCDS(t)
	_, _, err := runCmd("add", "sha256:short", "registry/app", "--url", url, "--insecure")
	if err == nil {
		t.Fatal("expected an invalid digest to be rejected")
	}
	if contains(*methods, http.MethodPost) {
		t.Fatal("must not call CDS with an invalid digest")
	}
}

func TestAddWrites(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	url, methods := recordingCDS(t)

	_, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !contains(*methods, http.MethodPost) {
		t.Fatalf("expected a POST, saw %v", *methods)
	}
}

func TestRemoveDryRunMakesNoCall(t *testing.T) {
	url, methods := recordingCDS(t)
	_, _, err := runCmd("remove", digA, digB, "--url", url, "--insecure", "--dry-run")
	if err != nil {
		t.Fatalf("remove --dry-run: %v", err)
	}
	if len(*methods) != 0 {
		t.Fatalf("dry-run must not call CDS, saw %v", *methods)
	}
}

func TestRemoveRejectsInvalidDigest(t *testing.T) {
	url, _ := recordingCDS(t)
	if _, _, err := runCmd("remove", "sha256:oops", "--url", url, "--insecure"); err == nil {
		t.Fatal("expected an invalid digest to be rejected")
	}
}

func TestRemoveProceedsWhenListFails(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	url, methods := listFailingCDS(t)

	_, _, err := runCmd("remove", digA, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("remove should still delete when the pre-check list fails: %v", err)
	}
	if !contains(*methods, http.MethodDelete) {
		t.Fatalf("expected a DELETE despite the failing pre-check list, saw %v", *methods)
	}
}

// --- upload ---

func TestUploadProceedsWhenListFailsForDiff(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	file := writeAllowlistFile(t, dir, coreImages())
	url, methods := listFailingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT despite the failing diff pre-fetch, saw %v", *methods)
	}
}

func TestUploadRequireOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	// Names none of the defaults, but satisfies the overridden requirement.
	file := writeAllowlistFile(t, dir, map[string]string{digA: "registry/team/myapp@" + digA})
	url, _ := servingCDS(t, nil)

	if _, _, err := runCmd("upload", file, "--url", url, "--insecure", "--require", "myapp", "--dry-run"); err != nil {
		t.Fatalf("upload with --require override failed: %v", err)
	}

	// And the override is enforced, not just accepted.
	if _, _, err := runCmd("upload", file, "--url", url, "--insecure", "--require", "otherapp", "--dry-run"); err == nil {
		t.Fatal("expected an unmet --require component to refuse the upload")
	}
}

func TestUploadRejectsBadFile(t *testing.T) {
	if _, _, err := runCmd("upload", filepath.Join(t.TempDir(), "nope.json"), "--url", "http://cds.example", "--insecure"); err == nil {
		t.Fatal("expected a missing upload file to fail")
	}
}

// --- lint (offline) ---

func TestLintOfflineWarningSurface(t *testing.T) {
	file := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"empty":{},
		"tagged":{"label":"docker.io/library/busybox:latest","containers":[
			{"digest":"`+digA+`","image":"docker.io/library/busybox:latest",
			 "command":{"policy":"any"},"args":{"policy":"any"},"paths":{"policy":"any"}}]},
		"other":{"containers":[
			{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
			 "paths":{"policy":"allow","read":["/**"]}},
			{"digest":"`+digB+`","command":{"policy":"deny"},"args":{"policy":"deny"}}]}}}`)

	out, _, err := runCmd("lint", file)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, want := range []string{
		`workload "empty" has no init or main containers`,
		`workload "tagged" label "docker.io/library/busybox:latest" is a tag`,
		`image "docker.io/library/busybox:latest" is a tag`,
		"the container can never start",
		`grants a root-subtree path "/**"`,
		"appears in 2 entries and one grants 'any'",
		"'any' (unconstrained) policy value(s) across all entries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lint output missing %q:\n%s", want, out)
		}
	}

	// --strict turns those warnings into a non-zero exit.
	if _, _, err := runCmd("lint", "--strict", file); err == nil {
		t.Fatal("expected --strict to turn warnings into a failure")
	}
}

func TestLintRejectsMissingAndInvalidFile(t *testing.T) {
	if _, _, err := runCmd("lint", filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected a missing lint file to fail")
	}
	bad := writeFile(t, "bad.json", `{"schema":"wrong/schema"}`)
	if _, _, err := runCmd("lint", bad); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("expected a schema error, got %v", err)
	}
}

// --- small helpers ---

func TestMatchedComponents(t *testing.T) {
	hits := matchedComponents("ghcr.io/confidential-dot-ai/CDS@sha256:1", defaultRequiredComponents)
	if len(hits) != 1 || hits[0] != "cds" {
		t.Fatalf("expected a case-insensitive [cds] match, got %v", hits)
	}
	if hits := matchedComponents("registry/team/app@sha256:2", defaultRequiredComponents); len(hits) != 0 {
		t.Fatalf("expected no match for a workload image, got %v", hits)
	}
}
