package getsecret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
)

// A malformed success body must not be mistaken for a secret.
func TestSecretResponseMustBeDecodable(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"value not base64", `{"value":"!!!"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startInventory(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/secrets" {
					w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
					return
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cfg := flowConfig(t, srv.URL)
			_, _, err := sidecar.Do(context.Background(), cfg.Config, http.DefaultClient, testKey(t), http.MethodGet, "/api/db")
			if err == nil {
				t.Fatal("an undecodable body was accepted as a secret")
			}
		})
	}
}

// The inventory is where the sandbox token comes from; without it there is no
// request to make.
func TestUnreachableInventoryFails(t *testing.T) {
	sidecar.SetInventoryEndpointForTest(t, func() string { return "unix://" + filepath.Join(t.TempDir(), "absent.sock") })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	}))
	defer srv.Close()
	cfg := flowConfig(t, srv.URL)
	_, _, err := sidecar.Do(context.Background(), cfg.Config, http.DefaultClient, testKey(t), http.MethodGet, "/api/db")
	if err == nil || !strings.Contains(err.Error(), "sandbox token") {
		t.Fatalf("err = %v, want a sandbox-token failure", err)
	}
}

// An unwritable output directory fails loudly rather than reporting success
// with no file on disk.
func TestWriteAllUnwritable(t *testing.T) {
	cfg := validConfig(t)
	cfg.OutDir = filepath.Join(cfg.OutDir, "readonly", "secrets")
	if err := os.MkdirAll(filepath.Dir(cfg.OutDir), 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the directory mode")
	}
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("v")}); err == nil {
		t.Fatal("an unwritable directory reported success")
	}
}

func TestWriteAllRejectsBadMode(t *testing.T) {
	cfg := validConfig(t)
	cfg.FileMode = "notamode"
	if err := writeAll(cfg, map[string][]byte{"DB": []byte("v")}); err == nil {
		t.Fatal("a bad file mode was accepted")
	}
}
