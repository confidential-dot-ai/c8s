package policymonitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// TestDetectGuestPlatformFollowsAttestationAPI pins that the sandbox-digests
// endpoint takes its TEE family from the in-guest attestation-api instead of
// assuming SEV-SNP: on a TDX guest the SNP assumption stamps a TDX envelope
// under the SNP TEE type and CDS refuses every sandbox token.
func TestDetectGuestPlatformFollowsAttestationAPI(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformTDX} {
		t.Run(string(platform), func(t *testing.T) {
			var gotReq remote.AttestRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/attest" {
					http.NotFound(w, r)
					return
				}
				if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
					t.Errorf("decode attest request: %v", err)
				}
				_ = json.NewEncoder(w).Encode(remote.AttestResponse{Platform: platform, Evidence: json.RawMessage(`{}`)})
			}))
			defer srv.Close()

			got, err := detectGuestPlatform(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("detectGuestPlatform: %v", err)
			}
			if got != string(platform) {
				t.Fatalf("platform = %q, want %q", got, platform)
			}
			if gotReq.Platform != remote.PlatformAuto {
				t.Fatalf("probe requested platform %q, want %q (let the attestation-api detect it)", gotReq.Platform, remote.PlatformAuto)
			}
		})
	}
}

func TestDetectGuestPlatformRejectsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(remote.AttestResponse{Evidence: json.RawMessage(`{}`)})
	}))
	defer srv.Close()
	if _, err := detectGuestPlatform(context.Background(), srv.URL); err == nil {
		t.Fatal("expected an error for an empty platform")
	}
}
