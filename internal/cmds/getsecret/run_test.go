package getsecret

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestParseSecretSpec(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spec     string
		wantName string
		wantPath string
		wantErr  bool
	}{
		{name: "simple", spec: "DB=/api/db", wantName: "DB", wantPath: "/api/db"},
		{name: "spaces are trimmed", spec: " DB = /api/db ", wantName: "DB", wantPath: "/api/db"},
		{name: "nested path", spec: "K=/a/b/c", wantName: "K", wantPath: "/a/b/c"},
		{name: "no separator", spec: "/api/db", wantErr: true},
		{name: "empty name", spec: "=/api/db", wantErr: true},
		// The name becomes a filename, so anything path-shaped is refused
		// rather than resolved.
		{name: "name is a path", spec: "a/b=/api/db", wantErr: true},
		{name: "name escapes the dir", spec: "..=/api/db", wantErr: true},
		{name: "relative store path", spec: "DB=api/db", wantErr: true},
		{name: "unclean store path", spec: "DB=/api/../etc", wantErr: true},
		{name: "wildcard store path", spec: "DB=/api/**", wantErr: true},
		{name: "percent-encoded store path", spec: "DB=/api%2Fdb", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSecretSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseSecretSpec(%q) = %+v, want an error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSecretSpec(%q): %v", tc.spec, err)
			}
			if got.Name != tc.wantName || got.Path != tc.wantPath {
				t.Fatalf("parseSecretSpec(%q) = %+v, want {%s %s}", tc.spec, got, tc.wantName, tc.wantPath)
			}
		})
	}
}

func validConfig(t *testing.T) config {
	t.Helper()
	return config{
		CDSURL:            "https://cds.example",
		AttestationApiURL: "http://127.0.0.1:8080",
		Secrets:           []secretRequest{{Name: "DB", Path: "/api/db"}},
		OutDir:            t.TempDir(),
		FileMode:          "0640",
		Attempts:          3,
		RetryInterval:     time.Second,
		RequestTimeout:    time.Second,
		InventoryTimeout:  time.Second,
	}
}

func TestValidate(t *testing.T) {
	if err := validate(ptr(validConfig(t))); err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config)
		want   string
	}{
		{"no cds url", func(c *config) { c.CDSURL = "" }, "--cds-url"},
		{"plaintext cds url", func(c *config) { c.CDSURL = "http://cds.example" }, "https"},
		{"no attestation api", func(c *config) { c.AttestationApiURL = "" }, "--attestation-api-url"},
		{"no secrets", func(c *config) { c.Secrets = nil }, "--secret"},
		{"zero attempts", func(c *config) { c.Attempts = 0 }, "--attempts"},
		{"zero retry interval", func(c *config) { c.RetryInterval = 0 }, "--retry-interval"},
		{"bad file mode", func(c *config) { c.FileMode = "rw-r-----" }, "--file-mode"},
		{"file mode out of range", func(c *config) { c.FileMode = "7777" }, "--file-mode"},
		{
			"repeated secret name",
			func(c *config) {
				c.Secrets = append(c.Secrets, secretRequest{Name: "DB", Path: "/api/other"})
			},
			"repeated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			tc.mutate(&cfg)
			err := validate(&cfg)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A trailing slash on --cds-url must not produce a double slash in the request
// path, which the server would reject as non-canonical.
func TestValidateTrimsURL(t *testing.T) {
	cfg := validConfig(t)
	cfg.CDSURL = "https://cds.example/"
	if err := validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CDSURL != "https://cds.example" {
		t.Fatalf("CDSURL = %q, want the trailing slash trimmed", cfg.CDSURL)
	}
}

func TestWriteAll(t *testing.T) {
	cfg := validConfig(t)
	values := map[string][]byte{
		"DB":    []byte("s3cret"),
		"OTHER": {0x00, 0xff, '\n', '"'}, // raw bytes, not text
	}
	if err := writeAll(cfg, values); err != nil {
		t.Fatal(err)
	}
	for name, want := range values {
		path := filepath.Join(cfg.OutDir, name)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode = %o, want 640", name, info.Mode().Perm())
		}
	}
}

// Nothing is left behind by the atomic write: a consumer polling the directory
// must not find a temp file and mistake it for its secret.
func TestWriteAllLeavesNoTempFiles(t *testing.T) {
	cfg := validConfig(t)
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("v")}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cfg.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "DB" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want just [DB]", names)
	}
}

// Rewriting is how a renewal or a re-fetch lands, so it must replace rather
// than fail or append.
func TestWriteAllOverwrites(t *testing.T) {
	cfg := validConfig(t)
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("second")}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(cfg.OutDir, "DB"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("value = %q, want the rewritten one", got)
	}
}

func TestWriteAllCreatesDir(t *testing.T) {
	cfg := validConfig(t)
	cfg.OutDir = filepath.Join(cfg.OutDir, "nested", "secrets")
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.OutDir, "DB")); err != nil {
		t.Fatal(err)
	}
}

func TestParseFileMode(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{in: "0640", want: 0o640},
		{in: "640", want: 0o640},
		{in: "0400", want: 0o400},
		{in: "0", wantErr: true},
		{in: "1000", wantErr: true},
		{in: "notamode", wantErr: true},
	} {
		got, err := parseFileMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseFileMode(%q) = %o, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("parseFileMode(%q) = %o, %v; want %o", tc.in, got, err, tc.want)
		}
	}
}

func ptr(c config) *config { return &c }

// The two endpoints are compiled: --workload-claims-guest picks a shape, never
// an address, so a wrong setting fails closed against a port nothing serves
// rather than redirecting redemption to a rogue inventory.
func TestEndpointSelectsCompiledShape(t *testing.T) {
	if got, want := (config{}).endpoint(), workloadclaims.InventoryEndpoint(); got != want {
		t.Errorf("node-CVM endpoint = %q, want the compiled unix socket %q", got, want)
	}
	guest := config{WorkloadClaimsGuest: true}.endpoint()
	if want := workloadclaims.GuestInventoryEndpoint(); guest != want {
		t.Errorf("kata endpoint = %q, want the compiled guest loopback %q", guest, want)
	}
	// workloadclaims refuses anything that is not one of the two compiled
	// endpoints, so a shape it rejects would fail every redemption. Use a real
	// key: a nil one fails at marshalling, short of the endpoint check.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = workloadclaims.FetchSandboxToken(t.Context(), guest, time.Millisecond, pub, []byte("nonce"))
	if err == nil {
		t.Fatal("expected the guest endpoint to fail with nothing listening")
	}
	if strings.Contains(err.Error(), "endpoint must be") {
		t.Fatalf("guest endpoint rejected by the compiled-endpoint check: %v", err)
	}
}
