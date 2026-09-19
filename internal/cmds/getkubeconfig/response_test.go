package getkubeconfig

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

type responseTransport struct {
	status int
	body   io.ReadCloser
}

func (tr responseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: tr.status, Body: tr.body, Header: make(http.Header)}, nil
}

type trackedResponseBody struct {
	reader io.Reader
	read   int
	closed bool
}

func (b *trackedResponseBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackedResponseBody) Close() error { b.closed = true; return nil }

func TestAttestationResponseBoundsEvidenceAndErrorBodies(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		status, size, maxRead int
		wantError             string
	}{
		{"short error", 503, 8, 8, "attest HTTP 503: " + strings.Repeat("x", 8)},
		{"exact error limit", 403, 1024, 1024, "attest HTTP 403: " + strings.Repeat("x", 1024)},
		{"truncated error", 500, 1025, 1025, "attest HTTP 500: " + strings.Repeat("x", 1024) + "... (truncated)"},
		{"large error reads only prefix", 502, (8 << 20) + 1, 1025, "attest HTTP 502: " + strings.Repeat("x", 1024) + "... (truncated)"},
		{"evidence", 200, 2048, 2048, ""},
		{"exact evidence limit", 200, 8 << 20, 8 << 20, ""},
		{"oversized evidence", 200, (8 << 20) + 1, (8 << 20) + 1, "attestation response exceeds 8 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Repeat([]byte("x"), tc.size)
			body := &trackedResponseBody{reader: bytes.NewReader(input)}
			client := &http.Client{Transport: responseTransport{status: tc.status, body: body}}
			req, err := http.NewRequest(http.MethodPost, "https://node.invalid/attest", nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readAttestationResponse(client, req)
			if tc.wantError != "" {
				if err == nil || err.Error() != tc.wantError {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
				if got != nil {
					t.Fatal("returned evidence from a failed response")
				}
			} else if err != nil || !bytes.Equal(got, input) {
				t.Fatalf("evidence size = %d, err = %v", len(got), err)
			}
			if body.read > tc.maxRead {
				t.Errorf("read %d bytes, limit %d", body.read, tc.maxRead)
			}
			if !body.closed {
				t.Error("response body was not closed")
			}
		})
	}
}

func TestAttestationResponsePreservesReadErrors(t *testing.T) {
	want := errors.New("response interrupted")
	for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
		body := &trackedResponseBody{reader: iotest.ErrReader(want)}
		client := &http.Client{Transport: responseTransport{status: status, body: body}}
		req, err := http.NewRequest(http.MethodPost, "https://node.invalid/attest", nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readAttestationResponse(client, req)
		if !errors.Is(err, want) || got != nil {
			t.Fatalf("status %d: got %v, err %v", status, got, err)
		}
		if !body.closed {
			t.Fatal("response body was not closed after read failure")
		}
	}
}
