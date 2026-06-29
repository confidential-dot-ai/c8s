package cmdsutil

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
