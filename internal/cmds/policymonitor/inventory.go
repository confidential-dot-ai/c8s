package policymonitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// sandboxIDAnnotations are the CRI annotation keys carrying the pod sandbox
// ID a container belongs to.
var sandboxIDAnnotations = []string{
	"io.kubernetes.cri.sandbox-id",  // containerd CRI
	"io.kubernetes.cri-o.SandboxID", // CRI-O
}

// admissionInventory implements workloadclaims.SandboxResolver for the kata
// guest — the same API shape nri-image-policy serves on node-CVM
// (docs/ratls.md, "Sandbox identity"). A kata guest
// holds exactly one pod, so there is no caller to disambiguate: peer PIDs are
// ignored, and the sandbox set is the guest's single sandbox ID, learned from
// the CRI annotations kata-agent hands the guest. It is fed from the same
// admission decisions policy-monitor already makes. It listens on a Unix
// socket inside the measured guest — no host-reachable socket and no
// peer-credential check are needed; the guest boundary is the isolation.
type admissionInventory struct {
	mu         sync.RWMutex
	containers map[string]string // container id -> image digest
	sandboxID  string            // the guest's single pod sandbox
}

func newAdmissionInventory() *admissionInventory {
	return &admissionInventory{containers: map[string]string{}}
}

// record notes an admitted container's digest — injected sidecars included, so
// the sandbox inventory is what actually runs in the guest.
func (b *admissionInventory) record(cid, digest string) {
	if digest == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.containers[cid] = digest
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
	for _, d := range b.containers {
		digests = append(digests, d)
	}
	slices.Sort(digests)
	return slices.Compact(digests), true, nil
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
	// A parse failure is a typo and stays fail-closed; empty is the explicit
	// dev opt-out, so tokens still flow and the guest can still be issued a
	// sandbox-bound leaf. Unlike runAllowlistRefresh, disabling here does not
	// degrade to a stricter state — it blocks issuance outright.
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil {
		logger.Error("sandbox tokens disabled: C8S_CDS_MEASUREMENTS invalid", "error", err)
		return nil
	}
	if len(measurements) == 0 {
		logger.Warn("C8S_CDS_MEASUREMENTS not set: the sandbox-digests endpoint answers ANY RA-TLS-attested caller, so any TEE that can reach this guest can read what it runs. UNSAFE outside development.")
	}
	addr, err := sandboxDigestsAddr(cfg)
	if err != nil {
		logger.Error("sandbox tokens disabled: no reachable digests address", "error", err)
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
	}, addr)
	if err != nil {
		logger.Error("sandbox tokens disabled: create signer failed", "error", err)
		return nil
	}
	logger.Info("sandbox tokens enabled", "digests_addr", addr)
	return signer
}

// sandboxDigestsAddr is the host:port every sandbox token names for CDS's
// digests callback — the guest's pod IP and the in-guest digests port.
func sandboxDigestsAddr(cfg *Config) (string, error) {
	cdsHost := cfg.CDSURL
	if u, err := url.Parse(cdsHost); err == nil && u.Host != "" {
		cdsHost = u.Host
	}
	return workloadclaims.ResolveAdvertiseAddr(cfg.SandboxDigestsAdvertiseHost, cfg.SandboxDigestsPort, cdsHost)
}

// startAdmissionInventory serves the token socket the guest bind-mounts into
// the pod's containers, the same transport nri-image-policy uses on node-CVM
// (docs/ratls.md). The shared socket path lets get-cert dial one compiled
// endpoint in both shapes.
func startAdmissionInventory(ctx context.Context, logger *slog.Logger, inventory *admissionInventory, socketPath string, signer *workloadclaims.SandboxTokenSigner) error {
	l, err := workloadclaims.ListenUnix(socketPath, workloadclaims.InventorySocketGID)
	if err != nil {
		return err
	}
	go func() {
		logger.Info("starting admission inventory", "socket", socketPath, "sandbox_tokens", signer != nil)
		if err := workloadclaims.ServeTokens(ctx, l, inventory, signer); err != nil {
			logger.Error("admission inventory error", "error", err)
		}
	}()
	return nil
}

// startSandboxDigests serves the CDS-facing digests endpoint inside the guest
// over mutually-attested RA-TLS (docs/ratls.md, "Sandbox identity").
func startSandboxDigests(ctx context.Context, logger *slog.Logger, cfg *Config, inventory *admissionInventory) error {
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil {
		return fmt.Errorf("parse CDS measurements: %w", err)
	}
	tlsCfg, certMgr, err := workloadclaims.DigestsServerTLSConfig(
		string(types.PlatformSnp),
		attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationServiceURL),
		cfg.AttestationServiceURL,
		measurements,
		0,
	)
	if err != nil {
		return err
	}
	warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = certMgr.WarmUp(warmupCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("warm up sandbox-digests cert: %w", err)
	}
	addr := net.JoinHostPort("", strconv.Itoa(cfg.SandboxDigestsPort))
	l, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	go func() {
		logger.Info("starting sandbox-digests endpoint", "addr", addr)
		if err := workloadclaims.ServeDigests(ctx, l, inventory); err != nil {
			logger.Error("sandbox-digests endpoint error", "error", err)
		}
	}()
	return nil
}
