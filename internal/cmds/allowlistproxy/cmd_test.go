package allowlistproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func TestProxyPreservesAuthorizedRequests(t *testing.T) {
	type observedRequest struct {
		method        string
		requestURI    string
		body          []byte
		authorization string
		contentType   string
		readErr       error
	}
	for _, tc := range []struct {
		name       string
		method     string
		requestURI string
		body       []byte
	}{
		{
			name:       "encoded workload path and raw query",
			method:     http.MethodPut,
			requestURI: "/allowlist/workloads/team%2Fmodel?version=one%2Ftwo&keep=one;two",
			body:       []byte(`{"containers":{"server":{}}}`),
		},
		{
			name:       "delete body",
			method:     http.MethodDelete,
			requestURI: "/allowlist/digests",
			body:       []byte(`{"digests":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := make(chan observedRequest, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				observed <- observedRequest{
					method:        r.Method,
					requestURI:    r.RequestURI,
					body:          body,
					authorization: r.Header.Get("Authorization"),
					contentType:   r.Header.Get("Content-Type"),
					readErr:       err,
				}
				w.Header().Set("ETag", `W/"7"`)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("created"))
			}))
			t.Cleanup(upstream.Close)

			target, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httptest.NewServer(newRouter(newReverseProxy(target, http.DefaultTransport, time.Second, slog.Default())))
			t.Cleanup(proxy.Close)

			req, err := http.NewRequest(tc.method, proxy.URL+tc.requestURI, bytes.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer operator-token")
			req.Header.Set("Content-Type", "application/json")
			// ReverseProxy must restore Authorization even if a malicious client
			// names it as hop-by-hop. nginx also forwards the header explicitly.
			req.Header.Set("Connection", "Authorization")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusCreated || string(gotBody) != "created" {
				t.Fatalf("response = %d %q", resp.StatusCode, gotBody)
			}
			if got := resp.Header.Get("ETag"); got != `W/"7"` {
				t.Fatalf("ETag = %q", got)
			}

			got := <-observed
			if got.readErr != nil {
				t.Fatal(got.readErr)
			}
			if got.method != tc.method {
				t.Errorf("method = %q, want %q", got.method, tc.method)
			}
			if got.requestURI != tc.requestURI {
				t.Errorf("request URI = %q, want %q", got.requestURI, tc.requestURI)
			}
			if !bytes.Equal(got.body, tc.body) {
				t.Errorf("body = %q, want %q", got.body, tc.body)
			}
			if got.authorization != "Bearer operator-token" {
				t.Errorf("Authorization = %q", got.authorization)
			}
			if got.contentType != "application/json" {
				t.Errorf("Content-Type = %q", got.contentType)
			}
		})
	}
}

func TestProxyExposesOnlyAllowlistPaths(t *testing.T) {
	hits := 0
	router := newRouter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/allowlist", want: http.StatusNoContent},
		{path: "/allowlist/digests", want: http.StatusNoContent},
		{path: "/allowlisted", want: http.StatusNotFound},
		{path: "/", want: http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s status = %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
	if hits != 2 {
		t.Fatalf("proxy hits = %d, want 2", hits)
	}
}

func TestParseCDSURL(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		wantErr string
	}{
		{raw: "https://c8s-cds.c8s-system.svc:8443"},
		{raw: "http://c8s-cds:8443", wantErr: `--cds-url must use https (RA-TLS), got scheme "http"`},
		{raw: "https://c8s-cds:8443/base", wantErr: "--cds-url must be an origin without credentials, path, query, or fragment"},
		{raw: "https://user@c8s-cds:8443", wantErr: "--cds-url must be an origin without credentials, path, query, or fragment"},
		{raw: "not a URL", wantErr: `invalid --cds-url "not a URL"`},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			_, err := parseCDSURL(tc.raw)
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestListenAddressRequiresLoopback(t *testing.T) {
	for _, tc := range []struct {
		host    string
		port    int
		want    string
		wantErr string
	}{
		{host: "127.0.0.1", port: 8801, want: "127.0.0.1:8801"},
		{host: "::1", port: 8801, want: "[::1]:8801"},
		{host: "0.0.0.0", port: 8801, wantErr: `--host must be a loopback IP, got "0.0.0.0"`},
		{host: "localhost", port: 8801, wantErr: `--host must be a loopback IP, got "localhost"`},
		{host: "127.0.0.1", port: 0, wantErr: "--port must be between 1 and 65535, got 0"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			got, err := listenAddress(tc.host, tc.port)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if got != tc.want {
					t.Fatalf("address = %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewHandlerRejectsBadMeasurement(t *testing.T) {
	bad := []string{"not-hex"}
	_, parseErr := ratls.ParseHexMeasurementsList(bad)
	_, err := newHandler(config{
		cdsURL:            "https://c8s-cds:8443",
		cdsMeasurements:   bad,
		attestationAPIURL: "http://attestation-api:8400",
		requestTimeout:    time.Second,
	}, slog.Default())
	want := "--cds-measurements: " + parseErr.Error()
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}
