package httputil

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadCappedBodyWithinLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	rec := httptest.NewRecorder()

	body, ok := ReadCappedBody(rec, req, 100)
	if !ok {
		t.Fatalf("ok = false, want true (status %d)", rec.Code)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
}

func TestReadCappedBodyExactlyAtLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	rec := httptest.NewRecorder()

	body, ok := ReadCappedBody(rec, req, 5)
	if !ok {
		t.Fatalf("ok = false at exact limit, want true")
	}
	if string(body) != "12345" {
		t.Errorf("body = %q, want 12345", body)
	}
}

func TestReadCappedBodyTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("123456"))
	rec := httptest.NewRecorder()

	body, ok := ReadCappedBody(rec, req, 5)
	if ok {
		t.Fatal("ok = true, want false for oversized body")
	}
	if body != nil {
		t.Errorf("body = %q, want nil", body)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (errReader) Close() error             { return nil }

func TestReadCappedBodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(errReader{}))
	req.Body = errReader{}
	rec := httptest.NewRecorder()

	body, ok := ReadCappedBody(rec, req, 100)
	if ok {
		t.Fatal("ok = true, want false on read error")
	}
	if body != nil {
		t.Errorf("body = %q, want nil", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
