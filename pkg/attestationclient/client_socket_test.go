package attestationclient

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

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

	// The custom client's own transport dials TCP: if it survived, every
	// request would fail, so a successful call proves the socket transport
	// took over.
	c := NewClientWithHTTP("unix://"+sock, &http.Client{})
	if _, err := c.Attest(context.Background(), types.AttestRequest{}); err != nil {
		t.Fatalf("Attest over unix socket with custom client failed: %v", err)
	}
}

// The unix rewrite swaps the transport, not the client: the caller's Timeout
// must still bound a wedged peer (accepts, never replies) — ratls-mesh's cert
// rotation leg relies on it.
func TestNewClientWithHTTPUnixKeepsCallerTimeout(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "attest.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close() // never answer
		}
	}()

	c := NewClientWithHTTP("unix://"+sock, &http.Client{Timeout: 150 * time.Millisecond})
	start := time.Now()
	if _, err := c.Health(context.Background()); err == nil {
		t.Fatal("Health succeeded against a wedged socket")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("caller timeout dropped on the unix path: Health returned after %s, want ~150ms", elapsed)
	}
}

func TestSocketOwnerAllowed(t *testing.T) {
	self := uint32(os.Getuid())
	for _, tc := range []struct {
		name string
		uid  uint32
		want bool
	}{
		{"root-owned", 0, true},
		{"self-owned", self, true},
		{"owned by another service account", self + 1, false},
	} {
		if got := socketOwnerAllowed(tc.uid); got != tc.want {
			t.Errorf("%s: socketOwnerAllowed(%d) = %v, want %v", tc.name, tc.uid, got, tc.want)
		}
	}
}

// End-to-end owner rejection: a swapped socket owned by a non-root,
// non-self uid must fail the dial-time validation.
func TestValidateVerifierSocketRejectsForeignOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("chown to a foreign uid requires root")
	}
	sock := filepath.Join(t.TempDir(), "attest.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(sock, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := validateVerifierSocket(sock); err == nil {
		t.Error("socket owned by a foreign uid accepted; want rejection")
	}
	if err := os.Chown(sock, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateVerifierSocket(sock); err != nil {
		t.Errorf("root-owned socket rejected: %v", err)
	}
}
