package policymonitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestDetectGuestPlatformFollowsAttestationAPI pins that the sandbox-digests
// endpoint takes its TEE family from the in-guest attestation-api instead of
// assuming SEV-SNP: on a TDX guest the SNP assumption stamps a TDX envelope
// under the SNP TEE type and CDS refuses every sandbox token.
func TestDetectGuestPlatformFollowsAttestationAPI(t *testing.T) {
	for _, platform := range []string{string(types.PlatformSnp), string(types.PlatformTdx)} {
		t.Run(platform, func(t *testing.T) {
			var gotReq types.AttestRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/attest" {
					http.NotFound(w, r)
					return
				}
				if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
					t.Errorf("decode attest request: %v", err)
				}
				_ = json.NewEncoder(w).Encode(types.AttestResponse{Platform: platform, Evidence: json.RawMessage(`{}`)})
			}))
			defer srv.Close()

			got, err := detectGuestPlatform(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("detectGuestPlatform: %v", err)
			}
			if got != platform {
				t.Fatalf("platform = %q, want %q", got, platform)
			}
			if gotReq.Platform != types.PlatformAuto {
				t.Fatalf("probe requested platform %q, want %q (let the attestation-api detect it)", gotReq.Platform, types.PlatformAuto)
			}
		})
	}
}

func TestDetectGuestPlatformRejectsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(types.AttestResponse{Evidence: json.RawMessage(`{}`)})
	}))
	defer srv.Close()
	if _, err := detectGuestPlatform(context.Background(), srv.URL); err == nil {
		t.Fatal("expected an error for an empty platform")
	}
}
