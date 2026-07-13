package allowlist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalallowlist "github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// newOperatorKeypair writes an operator EC private key to dir and returns its
// path plus the matching public key (what CDS would pin).
func newOperatorKeypair(t *testing.T, dir, name string) (keyPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	keyPath = filepath.Join(dir, name)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath, &key.PublicKey
}

// cdsTestServer wires the real CDS allowlist handler + operator key-pinning
// verifier + in-memory store behind an httptest server, mirroring production
// routing.
func cdsTestServer(t *testing.T, pinned []*ecdsa.PublicKey) (*httptest.Server, *internalallowlist.Store) {
	t.Helper()
	store, err := internalallowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	h := internalallowlist.Handler{
		Store:           &store,
		WriteAuthorizer: operatorauth.Verifier{Keys: pinned, ClockSkew: 30 * time.Second}.Authorize,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /allowlist", h.HandleList)
	mux.HandleFunc("POST /allowlist", h.HandleAdd)
	mux.HandleFunc("PUT /allowlist", h.HandleReplace)
	mux.HandleFunc("DELETE /allowlist", h.HandleDelete)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		store.Close()
	})
	return srv, &store
}

// TestUploadEndToEndWithPinnedKey drives the real CLI against the real CDS
// handler + verifier. It proves the operator token the client mints is accepted
// (signature under the pinned key + body binding) and the replace lands — the
// body-binding path is the fragile one: pbh must hash the exact bytes sent.
func TestUploadEndToEndWithPinnedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, store := cdsTestServer(t, []*ecdsa.PublicKey{pub})

	images := coreImages()
	file := writeAllowlistFile(t, dir, images)

	if _, _, err := runCmd("upload", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	_, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != len(images) {
		t.Fatalf("store has %d entries after upload, want %d", len(digests), len(images))
	}
}

// TestUploadRejectedWhenKeyNotPinned proves the auth boundary: an operator key
// whose public half CDS has not pinned is rejected, and the store is untouched.
func TestUploadRejectedWhenKeyNotPinned(t *testing.T) {
	dir := t.TempDir()
	_, pinnedPub := newOperatorKeypair(t, dir, "pinned.key") // pinned on CDS
	unpinnedKeyPath, _ := newOperatorKeypair(t, dir, "unpinned.key")
	srv, store := cdsTestServer(t, []*ecdsa.PublicKey{pinnedPub})

	file := writeAllowlistFile(t, dir, coreImages())
	if _, _, err := runCmd("upload", file, "--url", srv.URL, "--insecure", "--operator-key", unpinnedKeyPath); err == nil {
		t.Fatal("expected upload with an unpinned operator key to be rejected")
	}
	_, digests, _ := store.ListAll()
	if len(digests) != 0 {
		t.Fatalf("store mutated despite rejected auth: %d entries", len(digests))
	}
}

// TestRemoveWarnsOnComponentFloorImage drives the real CLI + CDS handler.
// Removing a digest whose served ref names a c8s component must warn that
// enforcement is unchanged (the floor keeps admitting it); removing a plain
// workload digest must not.
func TestRemoveWarnsOnComponentFloorImage(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, store := cdsTestServer(t, []*ecdsa.PublicKey{pub})

	cdsD, _ := types.ParseDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	workloadD, _ := types.ParseDigest("sha256:2222222222222222222222222222222222222222222222222222222222222222")
	if err := store.Add(cdsD, "ghcr.io/confidential-dot-ai/cds@"+cdsD.String()); err != nil {
		t.Fatalf("seed cds digest: %v", err)
	}
	if err := store.Add(workloadD, "registry.example.com/team/app@"+workloadD.String()); err != nil {
		t.Fatalf("seed workload digest: %v", err)
	}

	t.Run("component digest warns", func(t *testing.T) {
		_, stderr, err := runCmd("remove", cdsD.String(), "--url", srv.URL, "--insecure", "--operator-key", keyPath)
		if err != nil {
			t.Fatalf("remove: %v", err)
		}
		if !strings.Contains(stderr, "component floor image") {
			t.Errorf("expected component floor-image warning, stderr=%q", stderr)
		}
	})

	t.Run("workload digest does not warn", func(t *testing.T) {
		_, stderr, err := runCmd("remove", workloadD.String(), "--url", srv.URL, "--insecure", "--operator-key", keyPath)
		if err != nil {
			t.Fatalf("remove: %v", err)
		}
		if strings.Contains(stderr, "component floor image") {
			t.Errorf("unexpected floor-image warning for workload digest, stderr=%q", stderr)
		}
	})
}
