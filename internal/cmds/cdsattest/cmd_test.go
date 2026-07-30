package cdsattest

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeFixtureFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, []byte(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunErrors(t *testing.T) {
	fixture := writeFixtureFile(t)
	tests := []struct {
		name    string
		cfg     config
		wantSub string
	}{
		{
			name:    "front-door mode is required",
			cfg:     config{evidenceFixture: fixture},
			wantSub: "--front-door-mode",
		},
		{
			name:    "unknown front-door mode",
			cfg:     config{frontDoorMode: "public", evidenceFixture: fixture},
			wantSub: "--front-door-mode",
		},
		{
			name:    "no evidence source",
			cfg:     config{frontDoorMode: FrontDoorModeCDS},
			wantSub: "--attestation-api-url or --evidence-fixture",
		},
		{
			name:    "unreadable evidence fixture",
			cfg:     config{frontDoorMode: FrontDoorModeCDS, evidenceFixture: filepath.Join(t.TempDir(), "missing.json")},
			wantSub: "read evidence fixture",
		},
		{
			name:    "invalid upstream URL",
			cfg:     config{frontDoorMode: FrontDoorModeWebPKI, evidenceFixture: fixture, upstream: "ftp://backend"},
			wantSub: "upstream must be an http:// or https:// URL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("run() error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

// freePort grabs an ephemeral port that is free at the time of the call.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestRunServesUntilSignalled(t *testing.T) {
	fixture := writeFixtureFile(t)

	port := freePort(t)
	cfg := config{
		host:              "127.0.0.1",
		port:              port,
		logLevel:          "not-a-level", // exercises the newLogger fallback too
		frontDoorMode:     FrontDoorModeCDS,
		evidenceFixture:   fixture,
		platform:          "snp",
		generation:        "genoa",
		sessionTTL:        time.Minute,
		readHeaderTimeout: time.Second,
		upstream:          "http://127.0.0.1:9", // valid URL; never dialed in this test
	}

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	var resp *http.Response
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get(base + "/healthz")
		if err == nil {
			break
		}
		select {
		case runErr := <-done:
			t.Fatalf("run exited early: %v", runErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("server never came up: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}

	// The standalone cds-cert.pem discovery endpoint is gone: the bundle embeds
	// the exact chain committed by report_data.
	certResp, err := http.Get(base + "/.well-known/c8s/cds-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	certResp.Body.Close()
	if certResp.StatusCode != http.StatusNotFound {
		t.Fatalf("cds-cert.pem status = %d, want 404", certResp.StatusCode)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("run returned error after SIGTERM: %v", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down after SIGTERM")
	}
}
