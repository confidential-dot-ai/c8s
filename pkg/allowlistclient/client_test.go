package allowlistclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// stubAuth is a test Authorizer returning a fixed header, recording the
// method, path, and body it was asked to bind to.
type stubAuth struct {
	header    string
	gotMethod string
	gotPath   string
	gotBody   []byte
	callErr   error
}

func (s *stubAuth) Authorization(method, path string, body []byte) (string, error) {
	s.gotMethod = method
	s.gotPath = path
	s.gotBody = body
	return s.header, s.callErr
}

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com/api/")
	if c.baseURL != "http://example.com/api" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestListSuccess(t *testing.T) {
	digest1, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	digest2, _ := types.ParseDigest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.AllowlistListResponse{
			Version: "1.0",
			Digests: map[types.Digest]string{
				digest1: "image-a",
				digest2: "image-b",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %q", resp.Version)
	}
	if len(resp.Digests) != 2 {
		t.Fatalf("expected 2 digests, got %d", len(resp.Digests))
	}
}

func TestAddSuccess(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	auth := &stubAuth{header: "Bearer test-token"}

	var gotAuth string
	var gotBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	if err := c.Add(context.Background(), digest, "my-image", auth); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer test-token" {
		t.Fatalf("expected auth header %q, got %q", "Bearer test-token", gotAuth)
	}
	// The Authorizer must be handed the exact method, path, and bytes the
	// server received, so the token's bindings match on the wire.
	if string(auth.gotBody) != string(gotBody) {
		t.Fatalf("Authorizer saw body %q but server received %q", auth.gotBody, gotBody)
	}
	if auth.gotMethod != http.MethodPost || auth.gotPath != "/allowlist" {
		t.Fatalf("Authorizer saw %s %s, want POST /allowlist", auth.gotMethod, auth.gotPath)
	}
}

func TestReplaceSuccess(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	auth := &stubAuth{header: "Bearer test-token"}

	var gotMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	err := c.Replace(context.Background(), map[types.Digest]string{digest: "img"}, auth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("expected PUT, got %s", gotMethod)
	}
}

func TestDeleteSuccess(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	err := c.Delete(context.Background(), []types.Digest{digest}, &stubAuth{header: "Bearer test-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	err := c.Delete(context.Background(), []types.Digest{digest}, &stubAuth{header: "Bearer test-token"})
	if err == nil {
		t.Fatal("expected error")
	}

	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected StatusError, got %T: %v", err, err)
	}
	if statusErr.Status != 404 {
		t.Fatalf("expected status 404, got %d", statusErr.Status)
	}
}

func TestFetchAllowlistConditionalAcceptsJSONContentTypeWithCharset(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `W/"1"`)
		_ = json.NewEncoder(w).Encode(types.AllowlistListResponse{
			Version: "1",
			Digests: map[types.Digest]string{
				digest: "image-a",
			},
		})
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	wl, etag, notModified, err := c.FetchAllowlistConditional(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notModified {
		t.Fatal("expected 200 response, got notModified")
	}
	if etag != `W/"1"` {
		t.Fatalf("etag = %q, want W/\"1\"", etag)
	}
	if got := wl.Digests[digest.String()]; got != "image-a" {
		t.Fatalf("digest missing from allowlist: %q", got)
	}
}

func TestFetchAllowlistConditionalRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"big"`)
		w.WriteHeader(http.StatusOK)
		// Stream more bytes than the cap. The body is junk; we expect the
		// cap to trip before ParseJSON ever runs.
		chunk := strings.Repeat("a", 64*1024)
		written := int64(0)
		for written <= maxAllowlistResponseBytes {
			n, err := w.Write([]byte(chunk))
			if err != nil {
				return
			}
			written += int64(n)
		}
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, &http.Client{Timeout: 5 * time.Second})
	_, _, _, err := c.FetchAllowlistConditional(context.Background(), "")
	if !errors.Is(err, errAllowlistResponseTooLarge) {
		t.Fatalf("expected errAllowlistResponseTooLarge, got %v", err)
	}
}
