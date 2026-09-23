package cdspin

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// The URL is the one thing no pin can compensate for: a path or query in it
// would silently re-target every request, and plain http carries no RA-TLS
// evidence to check the pins against.
func TestParseURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "origin", raw: "https://cds.example.com:8443"},
		{name: "origin with a bare root path", raw: "https://cds.example.com:8443/"},
		{name: "empty", raw: "", wantErr: "invalid --cds-url"},
		{name: "http", raw: "http://cds.example.com:8443", wantErr: "must use https"},
		{name: "with a path", raw: "https://cds.example.com:8443/allowlist", wantErr: "without credentials, path, query, or fragment"},
		{name: "with a query", raw: "https://cds.example.com:8443?x=1", wantErr: "without credentials, path, query, or fragment"},
		{name: "with credentials", raw: "https://user:pw@cds.example.com:8443", wantErr: "without credentials, path, query, or fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseURL(tt.raw)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseURL(%q) = _, %v, want no error", tt.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseURL(%q) = _, %v, want an error mentioning %q", tt.raw, err, tt.wantErr)
			}
		})
	}
}

// Both sidecars must take the same flag names, or the router pod ends up with
// two different pins on the same CDS.
func TestFlagsSpelling(t *testing.T) {
	var cfg Config
	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	cfg.Flags(f)
	for _, name := range []string{"cds-url", "cds-measurements", "cds-rtmrs", "measurements-config"} {
		if f.Lookup(name) == nil {
			t.Errorf("--%s is not registered", name)
		}
	}
}

func TestClientRejectsContradictoryPins(t *testing.T) {
	cfg := Config{
		URL:                "https://cds.example.com:8443",
		MeasurementsConfig: "/does/not/matter",
		Measurements:       []string{"aa"},
	}
	_, err := cfg.Client("http://attestation-api", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "--cds-measurements") {
		t.Fatalf("Client() = _, %v, want the config/flat-pin conflict", err)
	}
}
