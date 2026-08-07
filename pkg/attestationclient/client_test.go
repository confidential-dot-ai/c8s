package attestationclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com/api/")
	if c.baseURL != "http://example.com/api" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestHealthSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.HealthResponse{
			Status:      "ok",
			TokenIssuer: true,
			Cache: types.CacheStats{
				VcekEntries:  5,
				ChainEntries: 3,
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected status ok, got %q", resp.Status)
	}
	if !resp.TokenIssuer {
		t.Fatal("expected TokenIssuer true")
	}
	if resp.Cache.VcekEntries != 5 {
		t.Fatalf("expected VcekEntries 5, got %d", resp.Cache.VcekEntries)
	}
}

func TestVerifySuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.VerifyResponse{
			Result: types.VerificationResult{
				Platform:       "snp",
				SignatureValid: true,
				Claims: types.Claims{
					LaunchDigest: "abc123",
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.Verify(context.Background(), types.VerifyRequest{
		Platform: "snp",
		Evidence: json.RawMessage(`{"test":true}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result.Platform != "snp" {
		t.Fatalf("expected platform snp, got %q", resp.Result.Platform)
	}
	if !resp.Result.SignatureValid {
		t.Fatal("expected SignatureValid true")
	}
	if resp.Result.Claims.LaunchDigest != "abc123" {
		t.Fatalf("expected LaunchDigest abc123, got %q", resp.Result.Claims.LaunchDigest)
	}
}

func TestVerifyAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(types.ErrorResponse{
			Error:   "internal_error",
			Message: "something went wrong",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Verify(context.Background(), types.VerifyRequest{})
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Status != 500 {
		t.Fatalf("expected status 500, got %d", apiErr.Status)
	}
	if apiErr.Response.Message != "something went wrong" {
		t.Fatalf("expected message 'something went wrong', got %q", apiErr.Response.Message)
	}
}

func TestVerifyUnexpectedError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Verify(context.Background(), types.VerifyRequest{})
	if err == nil {
		t.Fatal("expected error")
	}

	var unexpErr *UnexpectedError
	if !errors.As(err, &unexpErr) {
		t.Fatalf("expected UnexpectedError, got %T: %v", err, err)
	}
	if unexpErr.Status != 502 {
		t.Fatalf("expected status 502, got %d", unexpErr.Status)
	}
	if unexpErr.Text != "bad gateway" {
		t.Fatalf("expected text 'bad gateway', got %q", unexpErr.Text)
	}
}

func TestNoAuthHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no Authorization header, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.HealthResponse{Status: "ok"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyRequestError(t *testing.T) {
	c := NewClient("http://127.0.0.1:0/not-a-real-server")
	_, err := c.Verify(context.Background(), types.VerifyRequest{})
	if err == nil {
		t.Fatal("expected error")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("expected RequestError, got %T: %v", err, err)
	}
}

func TestAttestSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		var req types.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode attest request: %v", err)
		}
		if req.Platform != types.PlatformAuto {
			t.Errorf("platform = %q, want auto", req.Platform)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.AttestResponse{
			Platform: "snp",
			Evidence: json.RawMessage(`{"quote":"abc"}`),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.Attest(context.Background(), types.AttestRequest{
		ReportData: types.NewBase64Bytes([]byte("rd")),
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Platform != "snp" {
		t.Fatalf("platform = %q, want snp", resp.Platform)
	}
	if string(resp.Evidence) != `{"quote":"abc"}` {
		t.Fatalf("evidence = %s, want the returned evidence object", resp.Evidence)
	}
}

func TestAttestAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "attest_failed", Message: "boom"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Attest(context.Background(), types.AttestRequest{Platform: types.PlatformAuto})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", apiErr.Status)
	}
}

// TestRedirectStatusIsAPIError pins the success window at [200, 300): a 300
// response is an error, not a decodable success.
func TestRedirectStatusIsAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMultipleChoices)
		json.NewEncoder(w).Encode(types.ErrorResponse{Error: "redirected", Message: "no"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Health(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusMultipleChoices {
		t.Fatalf("status = %d, want 300", apiErr.Status)
	}
}
