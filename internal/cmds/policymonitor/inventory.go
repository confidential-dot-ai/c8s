package policymonitor

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// containerNameAnnotations are the CRI annotation keys carrying a container's
// name, used to exclude the webhook-injected sidecars from the workload digest.
var containerNameAnnotations = []string{
	"io.kubernetes.cri.container-name",  // containerd CRI
	"io.kubernetes.cri-o.ContainerName", // CRI-O
}

// sandboxIDAnnotations are the CRI annotation keys carrying the pod sandbox
// ID a container belongs to.
var sandboxIDAnnotations = []string{
	"io.kubernetes.cri.sandbox-id",  // containerd CRI
	"io.kubernetes.cri-o.SandboxID", // CRI-O
}

// admissionInventory serves the kata-guest workload-claims flow and the
// sandbox-identity surface (workloadclaims.SandboxResolver) — the same API
// shape nri-image-policy serves on node-CVM (docs/ratls.md). A kata guest
// holds exactly one pod, so there is no caller to disambiguate: peer PIDs are
// ignored, and the sandbox set is the guest's single sandbox ID, learned from
// the CRI annotations kata-agent hands the guest. It is fed from the same
// admission decisions policy-monitor already makes. It listens on a Unix
// socket inside the measured guest — no host-reachable socket and no
// peer-credential check are needed; the guest boundary is the isolation.
type admissionInventory struct {
	mu         sync.RWMutex
	containers map[string]workloadclaims.Container // container id -> name+digest
	sandboxID  string                              // the guest's single pod sandbox
}

func newAdmissionInventory() *admissionInventory {
	return &admissionInventory{containers: map[string]workloadclaims.Container{}}
}

// record notes an admitted container's name and digest — injected sidecars
// included; they are excluded at query time (ContainersForPeer), the same
// split nri-image-policy uses, so the sandbox inventory stays complete.
func (b *admissionInventory) record(cid, name, digest string) {
	if digest == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.containers[cid] = workloadclaims.Container{Name: name, Digest: digest}
}

// recordSandboxID notes the guest's pod sandbox ID (from the CRI annotations
// of any observed container, the pause included). First non-empty wins — the
// guest holds one pod, so later values can only agree.
func (b *admissionInventory) recordSandboxID(id string) {
	if id == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sandboxID == "" {
		b.sandboxID = id
	}
}

// ContainersForPeer returns every admitted, non-injected container in the
// guest's single pod. The peer PID is ignored: the guest boundary is the
// isolation, so there is nothing to bind the caller to.
func (b *admissionInventory) ContainersForPeer(_ workloadclaims.Peer) ([]workloadclaims.Container, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]workloadclaims.Container, 0, len(b.containers))
	for _, c := range b.containers {
		if workloadclaims.IsInjectedContainer(c.Name) {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// SandboxForPeer returns the guest pod's sandbox ID; the peer PID is ignored
// (single pod). Fails until a container has been observed, so a too-early
// token request fails closed instead of naming an empty sandbox.
func (b *admissionInventory) SandboxForPeer(_ workloadclaims.Peer) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sandboxID == "" {
		return "", fmt.Errorf("sandbox ID not yet observed")
	}
	return b.sandboxID, nil
}

// DigestsForSandbox answers the sandbox inventory for the guest's single
// sandbox: sorted, deduplicated digests of every recorded container, injected
// sidecars included. Any other sandbox ID is unknown.
func (b *admissionInventory) DigestsForSandbox(sandboxID string) ([]string, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sandboxID == "" || sandboxID != b.sandboxID {
		return nil, false, nil
	}
	digests := []string{}
	for _, c := range b.containers {
		digests = append(digests, c.Digest)
	}
	slices.Sort(digests)
	return slices.Compact(digests), true, nil
}

// containerName extracts a container's name from its OCI annotations, or ""
// when absent (then it is treated as a non-injected app container).
func containerName(annotations map[string]string) string {
	for _, key := range containerNameAnnotations {
		if v := annotations[key]; v != "" {
			return v
		}
	}
	return ""
}

// sandboxIDFromAnnotations extracts the pod sandbox ID from a container's OCI
// annotations, or "" when absent.
func sandboxIDFromAnnotations(annotations map[string]string) string {
	for _, key := range sandboxIDAnnotations {
		if v := annotations[key]; v != "" {
			return v
		}
	}
	return ""
}

// sandboxTokenSigner builds the inventory's sandbox-token signer over the same
// RA-TLS-pinned CDS access the allowlist refresh uses; its EAR comes from
// CDS's /attest-key via the in-guest attestation-service. Config problems
// disable tokens (nil signer) but never crash the monitor — the same
// fail-open-to-degraded posture as runAllowlistRefresh; get-cert then issues
// without a sandbox ID.
func sandboxTokenSigner(cfg *Config, logger *slog.Logger) *workloadclaims.SandboxTokenSigner {
	if cfg.CDSURL == "" {
		logger.Warn("sandbox tokens disabled: no CDS URL configured")
		return nil
	}
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil || len(measurements) == 0 {
		logger.Error("sandbox tokens disabled: C8S_CDS_MEASUREMENTS invalid or empty", "error", err)
		return nil
	}
	httpClient, err := ratls.NewVerifyingHTTPClient(measurements, cfg.AttestationServiceURL)
	if err != nil {
		logger.Error("sandbox tokens disabled: build RA-TLS client failed", "error", err)
		return nil
	}
	cdsClient := attestclient.NewClientWithHTTP(cfg.CDSURL, httpClient)
	attestationURL := cfg.AttestationServiceURL
	signer, err := workloadclaims.NewSandboxTokenSigner(func(ctx context.Context, pubDER []byte) (string, error) {
		return cdsClient.AttestKey(ctx, attestationURL, pubDER)
	})
	if err != nil {
		logger.Error("sandbox tokens disabled: create signer failed", "error", err)
		return nil
	}
	return signer
}

// startAdmissionInventory serves the inventory on a Unix socket the guest
// bind-mounts into the pod's containers, the same transport nri-image-policy
// uses on node-CVM (docs/ratls.md). The shared socket path lets get-cert dial
// one compiled endpoint in both shapes.
func startAdmissionInventory(ctx context.Context, logger *slog.Logger, inventory *admissionInventory, socketPath string, signer *workloadclaims.SandboxTokenSigner) error {
	l, err := workloadclaims.ListenUnix(socketPath, workloadclaims.InventorySocketGID)
	if err != nil {
		return err
	}
	go func() {
		logger.Info("starting admission inventory", "socket", socketPath, "sandbox_tokens", signer != nil)
		if err := workloadclaims.Serve(ctx, l, inventory, signer); err != nil {
			logger.Error("admission inventory error", "error", err)
		}
	}()
	return nil
}
