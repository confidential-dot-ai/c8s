package sidecar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// stubResolver is an inventory that vouches for one sandbox. The token route
// binds its caller by peer credentials, which a unix socket supplies; nothing
// here needs to disambiguate.
type stubResolver struct{}

func (stubResolver) SandboxForPeer(workloadclaims.Peer) (string, error) {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil
}

func (stubResolver) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}

// startInventory serves the real token route on a unix socket and points the
// sidecar at it.
func startInventory(t *testing.T) {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go workloadclaims.ServeTokens(ctx, l, stubResolver{}, workloadclaims.NewSignerHolder(signer))
	t.Cleanup(func() { cancel(); l.Close() })

	SetInventoryEndpointForTest(t, func() string { return "unix://" + sock })
}

func testPubKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

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
			_, _, err := Do(context.Background(), testConfig(srv.URL), http.DefaultClient, testPubKey(t), http.MethodGet, "/api/db")
			if err == nil {
				t.Fatal("an undecodable body was accepted as a secret")
			}
		})
	}
}

// The inventory is where the sandbox token comes from; without it there is no
// request to make.
func TestUnreachableInventoryFails(t *testing.T) {
	SetInventoryEndpointForTest(t, func() string { return "unix://" + filepath.Join(t.TempDir(), "absent.sock") })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	}))
	defer srv.Close()
	_, _, err := Do(context.Background(), testConfig(srv.URL), http.DefaultClient, testPubKey(t), http.MethodGet, "/api/db")
	if err == nil || !strings.Contains(err.Error(), "sandbox token") {
		t.Fatalf("err = %v, want a sandbox-token failure", err)
	}
}
