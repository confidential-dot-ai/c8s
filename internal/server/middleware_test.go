package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestLoggerCallsNextAndPreservesStatus(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("body"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	RequestLogger(next).ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
	if rec.Body.String() != "body" {
		t.Errorf("body = %q, want body", rec.Body.String())
	}
}

func TestRequestLoggerDefaultStatusOK(t *testing.T) {
	// A handler that writes without an explicit WriteHeader defaults to 200.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	RequestLogger(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestStatusWriterCapturesCode(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK}
	sw.WriteHeader(http.StatusNotFound)

	if sw.status != http.StatusNotFound {
		t.Errorf("captured status = %d, want 404", sw.status)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("underlying status = %d, want 404", rec.Code)
	}
}
