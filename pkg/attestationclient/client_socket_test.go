package attestationclient

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestNewClientUnixSocketTransport(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "attest.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	c := NewClient("unix://" + sock)
	if _, err := c.Verify(context.Background(), types.VerifyRequest{}); err != nil {
		t.Fatalf("Verify over unix socket failed: %v", err)
	}
}

func TestValidateVerifierSocket(t *testing.T) {
	dir := t.TempDir()

	// A real socket, owned by us and not world-writable, is accepted.
	good := filepath.Join(dir, "ok.sock")
	ln, err := net.Listen("unix", good)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateVerifierSocket(good); err != nil {
		t.Fatalf("valid socket rejected: %v", err)
	}

	// World-writable socket is rejected.
	if err := os.Chmod(good, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateVerifierSocket(good); err == nil {
		t.Error("world-writable socket accepted; want rejection")
	}

	// A regular file is not a socket.
	reg := filepath.Join(dir, "notasocket")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateVerifierSocket(reg); err == nil {
		t.Error("regular file accepted as socket; want rejection")
	}

	// A relative path is rejected outright.
	if err := validateVerifierSocket("relative.sock"); err == nil {
		t.Error("relative path accepted; want rejection")
	}

	// A symlink to the socket is not itself a socket (Lstat).
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := validateVerifierSocket(link); err == nil {
		t.Error("symlink accepted; want rejection")
	}
}

// A unix:// URL must use the socket transport even when the caller supplies a
// custom (TCP-dialing) HTTP client — e.g. attestclient passes its CDS client
// through, which could never reach a Unix socket.
func TestNewClientWithHTTPUnixSocketTransport(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "attest.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/attest", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// The custom client dials nothing: if it were used, every request would
	// fail, so a successful call proves the socket transport took over.
	c := NewClientWithHTTP("unix://"+sock, &http.Client{})
	if _, err := c.Attest(context.Background(), types.AttestRequest{}); err != nil {
		t.Fatalf("Attest over unix socket with custom client failed: %v", err)
	}
}
