package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	// Find a real binary on PATH for the "valid attestCmd" case.
	validCmd := "true" // /usr/bin/true exists on Linux/macOS

	tests := []struct {
		name         string
		attestCmd    string
		outboundPort int
		inboundPort  int
		certTTL      time.Duration
		wantErr      string // substring match; "" means no error
	}{
		{
			name:         "valid config",
			attestCmd:    validCmd,
			outboundPort: 15001,
			inboundPort:  15006,
			certTTL:      24 * time.Hour,
		},
		{
			name:         "empty attest-cmd",
			attestCmd:    "",
			outboundPort: 15001,
			inboundPort:  15006,
			certTTL:      24 * time.Hour,
			wantErr:      "--attest-cmd is required",
		},
		{
			name:         "attest-cmd not found",
			attestCmd:    "/nonexistent/binary/attest-sev-snp-does-not-exist",
			outboundPort: 15001,
			inboundPort:  15006,
			certTTL:      24 * time.Hour,
			wantErr:      "not found",
		},
		{
			name:         "same ports",
			attestCmd:    validCmd,
			outboundPort: 15001,
			inboundPort:  15001,
			certTTL:      24 * time.Hour,
			wantErr:      "must differ",
		},
		{
			name:         "cert-ttl too short",
			attestCmd:    validCmd,
			outboundPort: 15001,
			inboundPort:  15006,
			certTTL:      1 * time.Millisecond,
			wantErr:      "too short",
		},
		{
			name:         "cert-ttl exactly 1m",
			attestCmd:    validCmd,
			outboundPort: 15001,
			inboundPort:  15006,
			certTTL:      1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip attest-cmd path tests if the binary doesn't exist
			// (e.g., "true" might not be in PATH on some systems).
			if tt.wantErr == "" && tt.attestCmd != "" {
				if _, err := os.Stat(tt.attestCmd); err != nil {
					// Try exec.LookPath style
				}
			}

			err := validateConfig(tt.attestCmd, tt.outboundPort, tt.inboundPort, tt.certTTL)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
