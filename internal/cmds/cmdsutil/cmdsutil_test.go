package cmdsutil

import (
	"bytes"
	"context"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

func TestRunMainSuccess(t *testing.T) {
	called := false
	RunMain(func(args []string) error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("run was not called")
	}
}

func TestRunMainHelpDoesNotExit(t *testing.T) {
	// flag.ErrHelp must be swallowed (return, not os.Exit).
	RunMain(func(args []string) error {
		return flag.ErrHelp
	})
}

func TestRequireRAMBackedDir(t *testing.T) {
	dir := t.TempDir()
	err := RequireRAMBackedDir("--out-dir", dir)
	if fileutil.RequireRAMBacked(dir) == nil {
		if err != nil {
			t.Fatalf("RAM-backed dir refused: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "--out-dir") {
		t.Fatalf("want a --out-dir-prefixed refusal, got %v", err)
	}
}

func TestOpenRAMBackedDir(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRAMBackedDir("--out-dir", dir)
	if fileutil.RequireRAMBacked(dir) == nil {
		if err != nil {
			t.Fatalf("RAM-backed dir refused: %v", err)
		}
		defer root.Close()
		return
	}
	if err == nil || !strings.Contains(err.Error(), "--out-dir") {
		t.Fatalf("want a --out-dir-prefixed refusal, got %v", err)
	}
}

func TestValidateHTTPURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://example.com", false},
		{"https://example.com", false},
		{"ftp://example.com", true},
		{"example.com", true},
		{"", true},
	}
	for _, c := range cases {
		err := ValidateHTTPURL("--endpoint", c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateHTTPURL(%q) err = %v, wantErr = %v", c.url, err, c.wantErr)
		}
		if err != nil && !contains(err.Error(), "--endpoint") {
			t.Errorf("error %q should mention flag name", err.Error())
		}
	}
}

func TestParseFlagsSuccess(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	port := fs.Int("port", 0, "")
	if err := ParseFlags(fs, []string{"-port", "8080"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if *port != 8080 {
		t.Errorf("port = %d, want 8080", *port)
	}
}

func TestParseFlagsHelpReturnsErrHelp(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	err := ParseFlags(fs, []string{"-h"})
	if err != flag.ErrHelp {
		t.Errorf("err = %v, want flag.ErrHelp", err)
	}
}

func TestShutdownOnDoneTriggersShutdown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	httpSrv := &http.Server{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		ShutdownOnDone(ctx, httpSrv, time.Second)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownOnDone did not return after context cancel")
	}
	srv.Close()
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestValidateAttestationAPIURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://localhost:8400", false},
		{"https://attestation-api:8400", false},
		{"unix:///var/run/nri-image-policy/attestation-api.sock", false},
		{"unix://relative.sock", true},
		{"unix://", true},
		{"ftp://example.com", true},
		{"", true},
	}
	for _, c := range cases {
		err := ValidateAttestationAPIURL("--attestation-api-url", c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateAttestationAPIURL(%q) err = %v, wantErr = %v", c.url, err, c.wantErr)
		}
		if err != nil && !contains(err.Error(), "--attestation-api-url") {
			t.Errorf("error %q should mention flag name", err.Error())
		}
	}
}

func TestWarnIfCDSUnpinned(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, count := range []int{0, 1, 2} {
		logs.Reset()
		WarnIfCDSUnpinned(count, "unpinned development configuration")
		warned := strings.Contains(logs.String(), "unpinned development configuration")
		if warned != (count == 0) {
			t.Errorf("measurement count %d: warning=%t", count, warned)
		}
	}
}
