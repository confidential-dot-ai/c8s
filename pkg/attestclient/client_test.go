package attestclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lunal-dev/c8s/pkg/types"
)

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com/api/")
	if c.baseURL != "http://example.com/api" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.ChallengeResponse{
			Challenge: "dGVzdC1jaGFsbGVuZ2U=",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.Authenticate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Challenge != "dGVzdC1jaGFsbGVuZ2U=" {
		t.Fatalf("expected challenge 'dGVzdC1jaGFsbGVuZ2U=', got %q", resp.Challenge)
	}
}

func TestHealthzSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Healthz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected healthz to return true")
	}
}

func TestReadyzSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Readyz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected readyz to return true")
	}
}
