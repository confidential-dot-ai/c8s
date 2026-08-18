package policymonitor

import (
	"context"
	"crypto/sha512"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
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
	unresolved map[string]struct{}                        // container ids with no digest; cleared only by a later resolved record
	sandboxID  string                                     // the guest's single pod sandbox
	// refresh renders the allowlist-refresh posture. Set by runMonitor; nil
	// leaves the field off the wire rather than reporting a false "disabled".
	refresh func() workloadclaims.AllowlistRefresh
}

func newAdmissionInventory() *admissionInventory {
	return &admissionInventory{
		containers: map[string]string{},
		admitted:   map[string]workloadclaims.SandboxContainer{},
		unresolved: map[string]struct{}{},
	}
}

// record notes every container that ran in the guest — injected sidecars
// included, and denied containers too, so the sandbox inventory is what
// actually ran, not what passed the checks. A container with no resolved
// digest is tracked as unresolved and closes the sandbox's answer. argv is
// the effective OCI process.args the allowlist was evaluated against.
func (b *admissionInventory) record(cid, digest string, argv []string) {
	if cid == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if digest == "" {
		b.unresolved[cid] = struct{}{}
		return
	}
	delete(b.unresolved, cid)
	b.containers[cid] = digest
	c := workloadclaims.SandboxContainer{Digest: digest, Argv: argv}
	b.admitted[c.Key()] = c
}

// remove evicts a container whose bundle kata-agent has torn down. The
// admission record keeps it — it still ran in this guest — including an
// unresolved digest, so a container that stops before one resolves closes the
// sandbox's answer for the sandbox's life. See docs/secrets.md,
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
//
// An unresolved digest fails the whole answer rather than commit a subset as
// if it were the whole inventory.
func (b *admissionInventory) DigestsForSandbox(sandboxID string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sandboxID == "" || sandboxID != b.sandboxID {
		return nil, nil, false, nil
	}
	if len(b.unresolved) > 0 {
		return nil, nil, true, fmt.Errorf("sandbox %s admitted a container with no resolved image digest", sandboxID)
	}
	digests := []string{}
	containers := make([]workloadclaims.SandboxContainer, 0, len(b.admitted))
	for _, c := range b.admitted {
		digests = append(digests, c.Digest)
		containers = append(containers, c)
	}
	slices.Sort(digests)
	slices.SortFunc(containers, workloadclaims.SandboxContainer.Compare)
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

// installSandboxTokenSigner resolves the address this guest's sandbox tokens
// commit to, starts the digests endpoint CDS calls back on, and only then hands
// the signer to the token route. The key needs no credential of its own: CDS
// reads it from that endpoint on a privileged port, which is what establishes
// whose key it is.
//
// It runs after READY=1. The address comes from a routing-table lookup toward
// CDS, and the pod network it needs is installed by kata-agent's
// UpdateInterface RPC — a unit systemd holds behind this one. Resolving on the
// startup path therefore cannot succeed, and blocking there is what
// TimeoutStartSec + FailureAction=poweroff-force turns into a dead guest.
//
// Every failure disables the route rather than leaving it pending: a caller
// waiting on a signer that is not coming is worse than one told to proceed
// without a sandbox ID.
func installSandboxTokenSigner(ctx context.Context, cfg *Config, logger *slog.Logger, inventory *admissionInventory, signers *workloadclaims.SignerHolder, settle time.Time) {
	// A parse failure is a typo and stays fail-closed; empty is the explicit
	// dev opt-out, so tokens still flow and the guest can still be issued a
	// sandbox-bound leaf.
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil {
		logger.Error("sandbox tokens disabled: C8S_CDS_MEASUREMENTS invalid", "error", err)
		signers.Disable()
		return
	}
	if len(measurements) == 0 {
		logger.Warn("C8S_CDS_MEASUREMENTS not set: the sandbox-digests endpoint answers ANY RA-TLS-attested caller, so any TEE that can reach this guest can read what it runs. UNSAFE outside development.")
	}
	resolveCtx, cancel := context.WithDeadline(ctx, settle)
	host, err := resolveSandboxDigestsHostLate(resolveCtx, cfg, logger, sandboxDigestsHost)
	cancel()
	if err != nil {
		logger.Error("sandbox tokens disabled: no reachable digests host", "error", err)
		signers.Disable()
		return
	}
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		logger.Error("sandbox tokens disabled: create signer failed", "error", err)
		signers.Disable()
		return
	}
	// Before the route answers, not after: a token names this endpoint, and CDS
	// refuses one it cannot call back on. Issuing first would hand out tokens
	// that are guaranteed to be rejected.
	if err := startSandboxDigests(ctx, logger, cfg, inventory, signer, measurements); err != nil {
		logger.Error("sandbox-digests endpoint disabled; issuing without a sandbox ID rather than tokens CDS would refuse", "error", err)
		signers.Disable()
		return
	}
	signers.Set(signer)
	logger.Info("sandbox tokens enabled", "digests_host", host, "digests_port", workloadclaims.DigestsPort)
}

// sandboxDigestsHost is the guest IP every sandbox token names for CDS's
// digests callback.
func sandboxDigestsHost(ctx context.Context, cfg *Config) (string, error) {
	return workloadclaims.ResolveAdvertiseHost(ctx, cfg.SandboxDigestsAdvertiseHost, cfg.CDSURL)
}

// The wait for the guest network to reach a state where the routing-table
// lookup for CDS returns a real local IP.
//
// INVARIANT: advertiseHostLateBudget is deliberately LONGER than
// policy-monitor.service's TimeoutStartSec, which is only survivable because
// this lookup runs after READY=1. Moving it back onto the startup path would
// let systemd fail the unit at TimeoutStartSec, and FailureAction=poweroff-force
// turns that into a dead guest for every kata pod (#258).
// TestAdvertiseHostRunsOffTheStartupPath pins the two apart.
//
// Overridable in tests.
var (
	advertiseHostRetryInterval = 2 * time.Second
	advertiseHostLateBudget    = 90 * time.Second
	// Bounds the serial initdata wait + advertise-host lookup (90s+90s alone
	// overshoots) under get-cert's 2m --initial-retry-timeout, so the token
	// route settles before the caller stops asking.
	signerSettleBudget = 110 * time.Second
)

// resolveSandboxDigestsHostLate retries the routing-table lookup until the pod
// network exists. Unlike the startup-path version it replaced, waiting here can
// actually succeed: kata-agent installs the network from a unit ordered behind
// this one, so the route appears shortly after READY=1.
//
// It gives up at advertiseHostLateBudget so a guest that never gets a network
// degrades to "issues without a sandbox ID" instead of holding every fetcher
// open forever.
//
// lookup is sandboxDigestsHost; injected so tests can drive the retry loop
// without the resolver.
func resolveSandboxDigestsHostLate(ctx context.Context, cfg *Config, logger *slog.Logger, lookup func(context.Context, *Config) (string, error)) (string, error) {
	// Explicit host bypasses inference entirely — no reason to wait.
	if cfg.SandboxDigestsAdvertiseHost != "" {
		return lookup(ctx, cfg)
	}
	deadline := time.Now().Add(advertiseHostLateBudget)
	var lastErr error
	for attempt := 1; ; attempt++ {
		host, err := lookup(ctx, cfg)
		if err == nil {
			if attempt > 1 {
				logger.Info("advertise-host inference recovered", "attempt", attempt, "host", host)
			}
			return host, nil
		}
		lastErr = err
		if !time.Now().Add(advertiseHostRetryInterval).Before(deadline) {
			break
		}
		logger.Warn("advertise-host inference failed; retrying",
			"attempt", attempt, "retry_in", advertiseHostRetryInterval, "error", err)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(advertiseHostRetryInterval):
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
func startAdmissionInventory(ctx context.Context, logger *slog.Logger, inventory *admissionInventory, signers *workloadclaims.SignerHolder) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(workloadclaims.GuestTokenPort))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	go func() {
		logger.Info("starting admission inventory", "addr", addr, "sandbox_tokens", signers.Ready())
		if err := workloadclaims.ServeTokens(ctx, l, inventory, signers); err != nil {
			logger.Error("admission inventory error", "error", err)
		}
	}()
	return nil
}

// startSandboxDigests serves the CDS-facing digests endpoint inside the guest
// over mutually-attested RA-TLS (docs/ratls.md, "Sandbox identity").
//
// The endpoint's RA-TLS certificate stamps the guest's TEE family, and CDS
// verifies the evidence under that family's rules, so the platform is read
// from the in-guest attestation-api rather than assumed: a TDX guest whose
// leaf claimed SEV-SNP would carry a TDX envelope under the SNP TEE type, and
// CDS would refuse every sandbox token it signs.
func startSandboxDigests(ctx context.Context, logger *slog.Logger, cfg *Config, inventory *admissionInventory, signer *workloadclaims.SandboxTokenSigner, measurements [][]byte) error {
	platform, err := detectGuestPlatform(ctx, cfg.AttestationServiceURL)
	if err != nil {
		return fmt.Errorf("detect guest TEE platform: %w", err)
	}
	logger.Info("sandbox-digests endpoint platform", "platform", platform)
	return workloadclaims.StartDigestsEndpoint(ctx, logger, inventory, signer.PublicKeyDER(),
		platform,
		attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationServiceURL),
		cfg.AttestationServiceURL, measurements)
}

// detectGuestPlatform asks the in-guest attestation-api which TEE it is
// running on by generating one throwaway piece of evidence (platform "auto")
// and reading the platform it reports. Evidence generation is the same call
// every RA-TLS handshake makes, so this adds no new capability requirement.
func detectGuestPlatform(ctx context.Context, attestationServiceURL string) (string, error) {
	var probe [sha512.Size384]byte
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, attestationServiceURL, probe[:])
	if err != nil {
		return "", err
	}
	if resp.Platform == "" {
		return "", fmt.Errorf("attestation-api reported no platform")
	}
	return resp.Platform, nil
}
