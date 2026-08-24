package attestationclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestLiveSNPEntryEnforcement drives the real verification path against real
// SEV-SNP evidence: a config pinning the booted image is admitted, and one
// pinning any other image is refused. Set C8S_LIVE_ATTESTATION_URL to the
// attestation-api of a running CVM and C8S_LIVE_EVIDENCE to its evidence.
func TestLiveSNPEntryEnforcement(t *testing.T) {
	apiURL := os.Getenv("C8S_LIVE_ATTESTATION_URL")
	evidencePath := os.Getenv("C8S_LIVE_EVIDENCE")
	if apiURL == "" || evidencePath == "" {
		t.Skip("set C8S_LIVE_ATTESTATION_URL and C8S_LIVE_EVIDENCE to run against a live CVM")
	}

	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence types.AttestationEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}

	configPath := os.Getenv("C8S_LIVE_CONFIG")
	if configPath == "" {
		t.Fatal("set C8S_LIVE_CONFIG to the measurements config pinning the booted image")
	}
	pinned, err := measurements.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	client := attestationclient.NewClient(apiURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The evidence was requested with an all-zero REPORTDATA.
	var policy attestationclient.EvidencePolicy
	policy.Entries = pinned.Entries

	if _, err := client.VerifyEvidence(ctx, evidence, policy); err != nil {
		t.Fatalf("rejected the image it was booted from: %v", err)
	}

	// Flip one byte of every pinned digest: same shape, different image.
	wrong := make([]measurements.Entry, 0, len(pinned.Entries))
	for _, e := range pinned.Entries {
		d := append([]byte(nil), e.Digest...)
		d[0] ^= 0xff
		wrong = append(wrong, measurements.Entry{Name: e.Name, Digest: d, RTMRs: e.RTMRs})
	}
	policy.Entries = wrong
	_, err = client.VerifyEvidence(ctx, evidence, policy)
	if err == nil {
		t.Fatal("admitted a guest whose launch measurement is not pinned")
	}
	if !errors.Is(err, attestationclient.ErrMeasurementNotAllowed) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	t.Logf("unpinned image refused: %v", err)
}
