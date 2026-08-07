package policymonitor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
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
// (docs/ratls.md, "Sandbox identity"). A kata guest holds exactly one pod, so
// there is no caller to disambiguate: peer PIDs are ignored, and the sandbox
// set is the guest's single sandbox ID, learned from the CRI annotations
// kata-agent hands the guest. It is fed from the same admission decisions
// policy-monitor already makes. The token route is served on guest loopback —
// the guest boundary is the isolation, so no peer-credential check is needed.
type admissionInventory struct {
	mu         sync.RWMutex
	containers map[string]string                          // live container id -> image digest
	admitted   map[string]workloadclaims.SandboxContainer // key -> everything ever admitted
	sandboxID  string                                     // the guest's single pod sandbox
	// refresh renders the allowlist-refresh posture. Set by runMonitor; nil
	// leaves the field off the wire rather than reporting a false "disabled".
	refresh func() workloadclaims.AllowlistRefresh
}

func newAdmissionInventory() *admissionInventory {
	return &admissionInventory{
		containers: map[string]string{},
		admitted:   map[string]workloadclaims.SandboxContainer{},
	}
}

// record notes an admitted container — injected sidecars included, so the
// sandbox inventory is what actually ran in the guest. argv is the effective
// OCI process.args the allowlist was evaluated against.
func (b *admissionInventory) record(cid, digest string, argv []string) {
	if digest == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.containers[cid] = digest
	c := workloadclaims.SandboxContainer{Digest: digest, Argv: argv}
	b.admitted[c.Key()] = c
}

// remove evicts a container whose bundle kata-agent has torn down. The
// admission record keeps it — it still ran in this guest. See docs/secrets.md,
// "The report is a high-water mark".
func (b *admissionInventory) remove(cid string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.containers, cid)
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
// sandbox: every container ever admitted there, injected sidecars included, as
// a sorted deduplicated digest set plus per-container (digest, argv) detail.
// Any other sandbox ID is unknown.
func (b *admissionInventory) DigestsForSandbox(sandboxID string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sandboxID == "" || sandboxID != b.sandboxID {
		return nil, nil, false, nil
	}
	digests := []string{}
	containers := make([]workloadclaims.SandboxContainer, 0, len(b.admitted))
	for _, c := range b.admitted {
		digests = append(digests, c.Digest)
		containers = append(containers, c)
	}
	slices.Sort(digests)
	slices.SortFunc(containers, func(x, y workloadclaims.SandboxContainer) int {
		if x.Digest != y.Digest {
			return strings.Compare(x.Digest, y.Digest)
		}
		return slices.Compare(x.Argv, y.Argv)
	})
	return slices.Compact(digests), containers, true, nil
}

// AllowlistRefresh satisfies workloadclaims.AllowlistRefreshReporter: it puts
// "this guest is enforcing a frozen allowlist" on the CDS-facing digests
// endpoint, the one authenticated channel out of a guest whose journal the
// operator cannot read. Diagnostic only — CDS makes no issuance decision on it.
func (b *admissionInventory) AllowlistRefresh() (workloadclaims.AllowlistRefresh, bool) {
	if b.refresh == nil {
		return workloadclaims.AllowlistRefresh{}, false
	}
	return b.refresh(), true
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

// sandboxTokenSigner builds the guest's sandbox-token signer. The key needs no
// credential of its own: CDS reads it from this guest's digests endpoint on a
// privileged port, which is what establishes whose key it is. Config problems
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
	host, err := resolveSandboxDigestsHostWithRetry(cfg, logger)
	if err != nil {
		logger.Error("sandbox tokens disabled: no reachable digests host", "error", err)
		return nil
	}
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		logger.Error("sandbox tokens disabled: create signer failed", "error", err)
		return nil
	}
	logger.Info("sandbox tokens enabled", "digests_host", host, "digests_port", workloadclaims.DigestsPort)
	return signer
}

// sandboxDigestsHost is the guest IP every sandbox token names for CDS's
// digests callback.
func sandboxDigestsHost(cfg *Config) (string, error) {
	cdsHost := cfg.CDSURL
	if u, err := url.Parse(cdsHost); err == nil && u.Host != "" {
		cdsHost = u.Host
	}
	return workloadclaims.ResolveAdvertiseHost(cfg.SandboxDigestsAdvertiseHost, cdsHost)
}

// advertiseHostRetryBudget bounds the wait for the guest network to reach a
// state where the routing-table lookup for CDS returns a real local IP. Kata
// brings the pod network up after policy-monitor starts, so the first attempts
// hit `network is unreachable`; that must not permanently latch tokens off.
// Overridable in tests.
var (
	advertiseHostAttempts = 12
	advertiseHostBackoff  = 5 * time.Second
)

// resolveSandboxDigestsHostWithRetry keeps retrying the routing-table lookup
// while the guest's network is still being configured. It returns the last
// error only when every attempt in the budget failed — the caller then falls
// back to the same "sandbox tokens disabled" posture it always had.
func resolveSandboxDigestsHostWithRetry(cfg *Config, logger *slog.Logger) (string, error) {
	// Explicit host bypasses inference entirely — no reason to wait.
	if cfg.SandboxDigestsAdvertiseHost != "" {
		return sandboxDigestsHost(cfg)
	}
	var lastErr error
	for i := 1; i <= advertiseHostAttempts; i++ {
		host, err := sandboxDigestsHost(cfg)
		if err == nil {
			if i > 1 {
				logger.Info("advertise-host inference recovered", "attempt", i, "host", host)
			}
			return host, nil
		}
		lastErr = err
		if i < advertiseHostAttempts {
			logger.Warn("advertise-host inference failed; retrying",
				"attempt", i, "of", advertiseHostAttempts, "retry_in", advertiseHostBackoff, "error", err)
			time.Sleep(advertiseHostBackoff)
		}
	}
	return "", lastErr
}

// startAdmissionInventory serves the token route on the guest's loopback
// address, which the pod's containers share (docs/ratls.md). No shared
// filesystem is involved, and no configuration selects it: the port is
// compiled, so the untrusted host cannot disable the binding by withholding a
// value the way an env-gated socket path allowed.
//
// Loopback is sound here for the reason peer credentials are unnecessary: a
// kata guest holds exactly one pod, so there is no caller to tell apart.
func startAdmissionInventory(ctx context.Context, logger *slog.Logger, inventory *admissionInventory, signer *workloadclaims.SandboxTokenSigner) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(workloadclaims.GuestTokenPort))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	go func() {
		logger.Info("starting admission inventory", "addr", addr, "sandbox_tokens", signer != nil)
		if err := workloadclaims.ServeTokens(ctx, l, inventory, signer); err != nil {
			logger.Error("admission inventory error", "error", err)
		}
	}()
	return nil
}

// startSandboxDigests serves the CDS-facing digests endpoint inside the guest
// over mutually-attested RA-TLS (docs/ratls.md, "Sandbox identity").
func startSandboxDigests(ctx context.Context, logger *slog.Logger, cfg *Config, inventory *admissionInventory, signer *workloadclaims.SandboxTokenSigner) error {
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil {
		return fmt.Errorf("parse CDS measurements: %w", err)
	}
	return workloadclaims.StartDigestsEndpoint(ctx, logger, inventory, signer.PublicKeyDER(),
		string(types.PlatformSnp),
		attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationServiceURL),
		cfg.AttestationServiceURL, measurements)
}
