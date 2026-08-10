//go:build linux

package policymonitor

// Inotify watch + per-container decision logic.
//
// Topology: kata-agent writes /run/kata-containers/<cid>/config.json
// during do_create_container (rpc.rs:296 in kata-containers 3.30.0),
// before it forks the container's init. We watch the parent directory
// with IN_CREATE and parse config.json as soon as a new child appears.
//
// Order-of-events caveat
//
// The bundle directory is created when the guest pull starts
// (confidential_data_hub::pull_image), and config.json is written after
// add_storages returns — so the IN_CREATE event arrives one registry
// fetch before the spec exists. handleNewContainer therefore waits for
// config.json until the bundle goes away rather than on a deadline: a
// container we stopped waiting for is a container we never decided on.
//
// We use filepath.Walk on startup to seed the watcher with any
// directories already present (e.g. policy-monitor restarted by
// systemd while containers were already up).
//
// Watch-generation caveat
//
// kata-agent's create_sandbox replaces the whole watch dir
// (remove_dir_all + create_dir_all on CONTAINER_BASE, rpc.rs), and an
// inotify watch binds to the inode, not the path — so a watch
// installed at guest boot dies silently at the first sandbox, before
// any workload bundle exists. run() therefore watches in generations:
// a Remove/Rename event for the watch dir itself (with a periodic
// inode revalidation as backstop for dropped events) ends the
// generation, and the next one re-creates the dir if needed, re-Adds,
// and re-runs the seed pass so bundles created in the gap still get a
// decision. kata-agent replaces /run/kata-containers at sandbox
// creation.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/confidential-dot-ai/c8s/internal/kataspec"
	allowlistpkg "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// runMonitor is the long-running entry. It's package-private rather
// than exported because the only caller is the cobra subcommand in
// run.go; tests drive it indirectly through the helpers it composes
// (loadAllowlist, evaluateContainer, killer interfaces).
func runMonitor(ctx context.Context, cfg *Config) error {
	logger, err := certutil.NewJSONLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("log level: %w", err)
	}

	logger.Info("starting policy-monitor",
		"allowlist", cfg.AllowlistPath,
		"watch_dir", cfg.WatchDir,
		"cgroup_root", cfg.CgroupRoot,
	)

	a, warnings, err := loadAllowlist(cfg.AllowlistPath)
	if err != nil {
		return fmt.Errorf("load allowlist: %w", err)
	}
	for _, w := range warnings {
		logger.Warn("allowlist warning", "warning", w.Error())
	}
	logger.Info("allowlist loaded", "entries", a.Size())

	m := &monitor{
		cfg:       cfg,
		logger:    logger,
		allowlist: a,
		overlay:   &policyOverlay{},
		refresh:   &refreshState{reason: reasonNotYetStarted},
		killer:    newCgroupKiller(cfg.CgroupRoot),
		ready:     notifyReady,
		// The bundle directory appears when the guest pull STARTS and
		// config.json is written only once it finishes, so the wait is a
		// registry fetch. configReadDeadline is just how long to poll
		// tightly before backing off to configPendingInterval.
		configReadDeadline:    2 * time.Second,
		configReadInterval:    25 * time.Millisecond,
		configPendingInterval: time.Second,
		revalidateInterval:    10 * time.Second,
		// A denied container is re-killed until the kill lands or its bundle
		// is removed; killRetryDeadline bounds the tight phase.
		killRetryDeadline:   30 * time.Second,
		killRetryInterval:   500 * time.Millisecond,
		killPendingInterval: 10 * time.Second,
		// Well past the tight retry phase: a kill path still erroring here is
		// broken, not busy.
		killEscalateAfter: time.Minute,
		fatal:             make(chan error, 1),
	}

	// A monitor that cannot write cgroup.kill enforces nothing, so refuse to
	// come up rather than look healthy: c8s-ready.target Requires= this unit,
	// so a failed exit keeps the guest from admitting workload containers.
	if err := m.killer.selfTest(); err != nil {
		return fmt.Errorf("kill-path self-test: %w", err)
	}
	logger.Info("kill-path self-test passed", "cgroup_root", cfg.CgroupRoot)

	// Admission inventory (docs/ratls.md): the guest's sandbox identity, served
	// to the in-guest get-cert on loopback. Always on — a guest always holds a
	// pod that will ask, and gating it on configuration would let the untrusted
	// host switch it off.
	{
		m.inventory = newAdmissionInventory()
		m.inventory.refresh = func() workloadclaims.AllowlistRefresh { return m.refresh.report(a.Size()) }
		// The listener binds here, on the startup path, even though its signer
		// cannot exist yet: containers share the guest's network namespace, so
		// a workload that starts before this bind could claim
		// 127.0.0.1:8401 and answer as the inventory. Binding early and
		// signing later is what keeps that window shut (installSandboxTokenSigner).
		m.signers = workloadclaims.NewPendingSignerHolder()
		if cfg.CDSURL == "" {
			logger.Warn("sandbox tokens disabled: no CDS URL configured")
			m.signers.Disable()
		}
		if err := startAdmissionInventory(ctx, logger, m.inventory, m.signers); err != nil {
			return fmt.Errorf("start admission inventory: %w", err)
		}
	}

	// Hybrid refresh: when a CDS URL is configured (via the cloud-init
	// env the systemd unit loads), keep the allowlist current with CDS
	// additions on top of the baked seed. The goroutine shares the
	// *allowlist with m, whose merge is mutex-guarded. No CDS URL →
	// baked-seed-only and the network is never touched.
	if cfg.CDSURL != "" {
		// Both steps run here rather than on the startup path because the
		// document they need is written by kata-agent, which systemd holds
		// behind this unit's READY=1. cfg.CDSMeasurements is written only in
		// this goroutine, after the synchronous readers above have finished
		// with it.
		go func() {
			awaitInitDataMeasurements(ctx, logger, cfg)
			// Both need the measurements the document carries, and neither may
			// hold the other up: the signer waits on the pod network, the
			// refresh only on CDS answering.
			go installSandboxTokenSigner(ctx, cfg, logger, m.inventory, m.signers)
			runAllowlistRefresh(ctx, logger, cfg, a, m.overlay, m.refresh)
		}()
	} else {
		// Info, not Error: seed-only is the configured intent here, unlike the
		// failure paths in runAllowlistRefresh. Still recorded, so denies and
		// the digests endpoint report the frozen set either way.
		m.refresh.disable(reasonNoCDSURL)
		m.refresh.settle()
		logger.Info("allowlist refresh disabled (no CDS URL); enforcing baked seed only", "entries", a.Size())
	}

	return m.run(ctx)
}

// monitor encapsulates the runtime state. Exposed via dependency
// injection (killer) so the test suite can drive
// decisions against a tempdir without touching /sys/fs/cgroup or
// real PIDs.
type monitor struct {
	cfg                   *Config
	logger                *slog.Logger
	allowlist             *allowlist     // baked floor: additive digest set, never shrinks
	overlay               *policyOverlay // latest CDS pull's workload argv policy
	refresh               *refreshState  // whether the allowlist still tracks CDS
	killer                containerKiller
	inventory             *admissionInventory          // sandbox identity + digests (docs/ratls.md); always set
	signers               *workloadclaims.SignerHolder // token signer, installed once the pod network resolves
	ready                 func() error                 // systemd READY=1; nil outside the unit
	readyOnce             sync.Once
	fatal                 chan error // an enforcement failure the process must exit on
	killEscalateAfter     time.Duration
	configReadDeadline    time.Duration
	configReadInterval    time.Duration
	configPendingInterval time.Duration
	revalidateInterval    time.Duration
	killRetryDeadline     time.Duration
	killRetryInterval     time.Duration
	killPendingInterval   time.Duration
}

// policyOverlay holds the Index of the latest CDS pull that advanced the epoch.
// The baked floor stays authoritative for digest-only admission; the overlay
// adds the pulled document's workload argv policy. Read by per-container
// decision goroutines, replaced by the single refresh goroutine.
type policyOverlay struct {
	mu      sync.RWMutex
	idx     *allowlistpkg.Index
	version uint64
}

func (o *policyOverlay) index() *allowlistpkg.Index {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.idx
}

// apply installs al's Index when version advances past the last applied — epoch
// anti-rollback; a lower or equal version is ignored. The first apply always
// installs. Reports whether it applied.
// apply replaces the overlay with the pulled policy only when the version
// advances the epoch, so a withheld/rolled-back CDS can't reinstate a looser
// policy. The version is process-local (zero until the first apply), so rollback
// is rejected only within a process lifetime: after a (re)start the first pull is
// trusted whatever its version, then state re-syncs from CDS. A guest reboot is a
// fresh CVM, so this resets every boot; a reboot-durable guarantee needs an
// attested freshness/monotonic-counter mechanism, out of scope here.
func (o *policyOverlay) apply(al *allowlistpkg.Allowlist, version uint64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.idx != nil && version <= o.version {
		return false
	}
	o.idx = al.BuildIndex()
	o.version = version
	return true
}

// admits reports whether a container may run. The baked floor (additive digest
// set) admits by digest alone; otherwise the pulled overlay's Index decides on
// the whole observation — digest, argv, bind-mount destinations and env names.
// With no overlay (CDS refresh disabled, or no successful pull yet) only the
// baked floor admits — behavior from t=0.
func (m *monitor) admits(rc allowlistpkg.RunningContainer) bool {
	if m.allowlist.Contains(rc.Digest) {
		return true
	}
	if idx := m.overlay.index(); idx != nil {
		return idx.AdmitsContainer(rc)
	}
	return false
}

func (m *monitor) run(ctx context.Context) error {
	for {
		done, err := m.watch(ctx)
		if done || err != nil {
			return err
		}
		// Watch generation invalidated: the watch dir was replaced
		// under us. Loop to re-establish; the next generation re-seeds,
		// so bundles created in the gap still get a decision.
	}
}

// watch runs one watch generation: create the dir if missing, install
// the inotify watch, seed, then serve events until the context ends
// (done=true), the watch dies in a way a fresh generation can fix
// (done=false, err=nil), or an unrecoverable error occurs.
func (m *monitor) watch(ctx context.Context) (done bool, err error) {
	if err := os.MkdirAll(m.cfg.WatchDir, 0o755); err != nil {
		return false, fmt.Errorf("create watch dir %s: %w", m.cfg.WatchDir, err)
	}

	// Record the watched inode's identity BEFORE Add: if kata-agent
	// swaps the dir between the two calls, SameFile below fails on the
	// first revalidation tick and we converge via one extra generation
	// — the reverse order could record the new inode while watching the
	// dead one, and never recover.
	watchedFI, err := os.Stat(m.cfg.WatchDir)
	if err != nil {
		return false, fmt.Errorf("stat watch dir %s: %w", m.cfg.WatchDir, err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return false, fmt.Errorf("create inotify watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(m.cfg.WatchDir); err != nil {
		return false, fmt.Errorf("watch %s: %w", m.cfg.WatchDir, err)
	}

	// Seed: process directories that already exist. Important when
	// policy-monitor was restarted by systemd while containers were
	// running, and on every re-watch after the dir was replaced — we
	// shouldn't grandfather containers in just because we missed their
	// CREATE event. The fact that they're still around means kata-agent
	// considers them live, so we should make a decision on each.
	if err := m.seedExisting(ctx); err != nil {
		// Non-fatal: if we can't walk for some reason (permission,
		// transient FS error), log and keep going. New containers
		// from this point on are still observed via inotify.
		m.logger.Warn("seed existing containers failed", "error", err)
	}

	// The watch is installed and the seed pass has dispatched, so every bundle
	// kata-agent creates from here gets a decision. kata-agent's start job is
	// waiting on this (see notify.go).
	m.signalReady()

	// Backstop for the event path below: if the Remove/Rename for the
	// watch dir itself is dropped (e.g. inside a queue overflow), a
	// periodic inode identity check still notices the swap.
	interval := m.revalidateInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	revalidate := time.NewTicker(interval)
	defer revalidate.Stop()

	watchDirGone := func(reason string) (bool, error) {
		m.logger.Warn("watch dir replaced; re-establishing watch and re-seeding",
			"watch_dir", m.cfg.WatchDir, "reason", reason)
		return false, nil
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("policy-monitor stopping", "reason", ctx.Err())
			return true, nil

		case err := <-m.fatal:
			return false, err

		case evt, ok := <-watcher.Events:
			if !ok {
				return false, errors.New("watcher events channel closed")
			}
			// kata-agent's create_sandbox does remove_dir_all +
			// create_dir_all on the watch dir; the Remove/Rename of the
			// dir itself is the generation's death notice (inotify
			// watches bind to the inode, so the recreated dir is
			// unwatched).
			if evt.Op.Has(fsnotify.Remove|fsnotify.Rename) && filepath.Clean(evt.Name) == filepath.Clean(m.cfg.WatchDir) {
				return watchDirGone("inotify " + evt.Op.String())
			}
			// A bundle disappearing means its container is gone; drop it
			// from the inventory so /digests answers what the sandbox is
			// running rather than everything it ever ran. The watch dir's
			// own removal was handled above, so this is a child path.
			if evt.Op.Has(fsnotify.Remove|fsnotify.Rename) && m.pathLooksLikeContainer(evt.Name) {
				if m.inventory != nil {
					m.inventory.remove(filepath.Base(filepath.Clean(evt.Name)))
				}
				continue
			}
			// We only care about new entries appearing under the
			// watched directory. IN_CREATE covers both dirs and
			// files — we accept either and let pathLooksLikeContainer
			// filter the side artifacts (cleanup work files,
			// kata-agent's "shared" subdir).
			if !evt.Op.Has(fsnotify.Create) {
				continue
			}
			if !m.pathLooksLikeContainer(evt.Name) {
				m.logger.Debug("ignoring non-container path", "path", evt.Name)
				continue
			}
			// We don't gate kata-agent — process the event in a
			// goroutine so a slow read on one container doesn't
			// throttle our reaction time on another. The goroutine
			// is bounded by the context.
			go m.handleNewContainer(ctx, evt.Name)

		case err, ok := <-watcher.Errors:
			if !ok {
				return false, errors.New("watcher errors channel closed")
			}
			// Fail closed on queue overflow. IN_Q_OVERFLOW means the
			// kernel dropped CREATE events we never saw, so a container
			// that landed during the burst would otherwise run with no
			// decision made. Re-run the seed pass to re-scan the watch
			// dir and make a decision for everything currently present
			// (idempotent — see seedExisting). If the rescan itself
			// fails we exit non-zero and let systemd restart + reseed
			// rather than continue half-blind. The dropped events may
			// also include the watch dir's own Remove — check identity
			// too rather than wait for the next tick.
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				m.logger.Warn("inotify queue overflow; rescanning watch dir to recover dropped events")
				if serr := m.seedExisting(ctx); serr != nil {
					return false, fmt.Errorf("rescan after inotify overflow: %w", serr)
				}
				if fi, serr := os.Stat(m.cfg.WatchDir); serr != nil || !os.SameFile(watchedFI, fi) {
					return watchDirGone("identity check after overflow")
				}
				continue
			}
			m.logger.Warn("inotify error", "error", err)

		case <-revalidate.C:
			if fi, serr := os.Stat(m.cfg.WatchDir); serr != nil || !os.SameFile(watchedFI, fi) {
				return watchDirGone("periodic identity check")
			}
		}
	}
}

// abort reports a condition the process cannot enforce through. The watch loop
// returns it, runMonitor exits non-zero, and the unit escalates from there.
// Buffered and non-blocking: the first caller wins and later ones are noise on
// a process already on its way down.
func (m *monitor) abort(err error) {
	m.logger.Error("enforcement is broken; exiting so the unit can take the guest down", "error", err)
	select {
	case m.fatal <- err:
	default:
	}
}

// signalReady notifies systemd once, on the first watch generation. A failed
// notification leaves the unit un-started until TimeoutStartSec elapses, which
// fails it and powers the guest off.
func (m *monitor) signalReady() {
	m.readyOnce.Do(func() {
		if m.ready == nil {
			return
		}
		if err := m.ready(); err != nil {
			m.logger.Error("systemd readiness notification failed", "error", err)
		}
	})
}

// seedExisting walks the watch dir at startup and dispatches a
// decision for every child directory present. Idempotent — kata-agent
// keeps the bundle around until the container is removed, and we make
// a fresh decision either way (allowlisted = nothing happens; denied
// = kill, but the kill is a no-op if the init has already exited).
func (m *monitor) seedExisting(ctx context.Context) error {
	entries, err := os.ReadDir(m.cfg.WatchDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		full := filepath.Join(m.cfg.WatchDir, e.Name())
		if !m.pathLooksLikeContainer(full) {
			continue
		}
		// One goroutine per bundle, same as the event path: a decision now
		// waits for the container's image pull, and the watcher must keep
		// serving events meanwhile.
		go m.handleNewContainer(ctx, full)
	}
	return nil
}

// pathLooksLikeContainer applies a coarse filter: the path must be a
// direct child of WatchDir whose basename is a container id the baked
// kata-agent policy admits (kataspec.ValidContainerID). Anything else is
// a sibling artifact (e.g. /run/kata-containers/shared) that will never
// grow a config.json.
func (m *monitor) pathLooksLikeContainer(path string) bool {
	rel, err := filepath.Rel(m.cfg.WatchDir, path)
	if err != nil {
		return false
	}
	if strings.ContainsAny(rel, string(os.PathSeparator)) {
		return false
	}
	if rel == "." || rel == "" {
		return false
	}
	return kataspec.ValidContainerID(rel)
}

// handleNewContainer runs the full decision for one container
// directory. Synchronous from the caller's POV; the caller wraps it
// in a goroutine.
func (m *monitor) handleNewContainer(ctx context.Context, dir string) {
	cid := filepath.Base(dir)
	configPath := filepath.Join(dir, "config.json")

	spec, err := m.readConfigJSON(ctx, dir)
	if err != nil {
		// A config.json that EXISTS but cannot be read or parsed (malformed
		// JSON, permission games, a symlink that does not resolve) means we
		// cannot determine the image digest for a container that clearly has a
		// bundle. Fail closed: deny (kill) rather than let it run unmonitored.
		// Lstat, not Stat: a dangling symlink is a name the host planted, not
		// an absent file. Reaching here with the name absent means the bundle
		// itself went away, or we are shutting down — nothing to decide.
		if _, statErr := os.Lstat(configPath); statErr == nil {
			m.logger.Warn("deny container: config.json present but unreadable/malformed", "cid", cid, "path", configPath, "error", err)
			m.deny(ctx, dir)
			return
		}
		m.logger.Info("skip: bundle went away before config.json appeared", "cid", cid, "path", configPath, "error", err)
		return
	}

	// The pod sandbox (pause) container is out of allowlist scope. In
	// guest-pull mode (which c8s forces) kata-agent runs the pause baked
	// into the dm-verity rootfs for any container it deems a sandbox (see
	// isSandbox), so the sandbox's integrity comes from the launch
	// measurement, not a digest on the allowlist — and the host can't
	// substitute it. Skip it, identified exactly the way kata does so a
	// mislabelled workload can't slip through (kata would run the measured
	// pause for it, not the host's image). Checked before extractDigest
	// because the pause carries no image-name annotation.
	// Every container (the pause included) names its pod sandbox in the CRI
	// annotations; capture it for the inventory's sandbox-identity surface.
	if m.inventory != nil {
		m.inventory.recordSandboxID(sandboxIDFromAnnotations(spec.Annotations))
	}

	if kataspec.IsSandbox(spec.Annotations) {
		m.logger.Info("allow sandbox (pause) container — measured via rootfs, not allowlisted", "cid", cid)
		m.recordVerdict(dir, verdictAllow)
		return
	}

	digest, ok := kataspec.PullDigest(spec.Annotations)
	if !ok {
		// A non-sandbox container whose pull reference is missing or carries a
		// tag rather than a digest (the sandbox/pause container is handled
		// above). Deny: a tag names whatever the registry serves the guest at
		// pull time, so there is no digest to check. The baked kata-agent
		// policy rejects the same request earlier, so reaching here means the
		// policy was not in force.
		// Name the annotation keys, not just the missing reference: this denial
		// also fires when the spec is not the one c8s expects at all (a pause
		// container whose type marker is absent lands here and takes the whole
		// sandbox down), and the keys are the only way to tell those apart from
		// outside the guest. Keys only — values carry pod-identifying data.
		m.logger.Warn("deny container: image reference is absent or not digest-pinned",
			"cid", cid, "reference", spec.Annotations[kataspec.PullReferenceKey],
			"annotation_keys", slices.Sorted(maps.Keys(spec.Annotations)))
		m.deny(ctx, dir)
		return
	}

	// What the container actually runs, as the allowlist describes it. Floor
	// digests ignore all of it; workload digests are gated on the whole set.
	rc := allowlistpkg.RunningContainer{
		Digest:     digest,
		BindMounts: bindMountDestinations(spec.Mounts),
	}
	if spec.Process != nil {
		rc.Argv = spec.Process.Args
		rc.EnvNames = envNames(spec.Process.Env)
	}
	// A container is created seconds after its guest boots, while the first
	// CDS pull is still failing for want of a pod network, so the allowlist a
	// first verdict sees is the baked seed. Deciding on it would refuse every
	// operator-added digest for the life of a pod that does not retry. Wait
	// for a landed refresh — but only when about to deny, so an admitted
	// container never pays for it, and only up to a budget, after which the
	// seed is the answer and the deny stands.
	if !m.admits(rc) {
		m.refresh.awaitSettled(ctx, refreshSettleBudget)
	}
	if m.admits(rc) {
		m.logger.Info("allow container", "cid", cid, "digest", digest)
		if m.inventory != nil {
			m.inventory.record(cid, digest, rc.Argv)
		}
		m.recordVerdict(dir, verdictAllow)
		return
	}
	// Name every field the decision looked at: a container denied on its mounts
	// or environment reported as "digest/argv" would send an operator hunting
	// the wrong thing.
	m.logger.Warn("deny container: not admitted by digest, argv, mounts or env",
		append([]any{
			"cid", cid, "digest", digest, "argv", rc.Argv,
			"bind_mounts", rc.BindMounts, "env_names", rc.EnvNames,
		}, m.frozenAttrs()...)...)
	m.deny(ctx, dir)
}

// deny records the verdict, then kills. Order matters: the verdict is what
// stops the container reaching execve, and kill retries until the cgroup is
// confirmed empty — so writing it second would leave the agent free to start
// the container while the kill is still being attempted.
func (m *monitor) deny(ctx context.Context, dir string) {
	m.recordVerdict(dir, verdictDeny)
	m.kill(ctx, dir)
}

// frozenAttrs annotates a deny with the fact that the allowlist never left the
// baked seed, when that is why the deny happened. Without it a frozen guest and
// a genuinely-unlisted image produce identical lines — and once the kill lands
// a frozen guest denies everything at once.
func (m *monitor) frozenAttrs() []any {
	reason := m.refresh.frozenReason()
	if reason == "" {
		return nil
	}
	return []any{"allowlist_frozen", true, "frozen_reason", reason, "allowlist_entries", m.allowlist.Size()}
}

// kill resolves the denied container's cgroup and terminates it as a unit,
// re-attempting until the kill is confirmed, the bundle directory goes away
// (kata-agent removed the container), or ctx ends. Repeat failures are logged
// once per escalation, not once per attempt.
//
// A kill mechanism that keeps erroring past killEscalateAfter is not a slow
// container, it is enforcement that no longer works — cgroup.kill returning
// EROFS under a remounted hierarchy is the case that motivated the boot-time
// selfTest. Escalate: the process exits non-zero, and the unit turns that into
// restarts and then poweroff (see policy-monitor.service). selfTest runs again
// on each restart, so a hierarchy that is still read-only fails there instead.
func (m *monitor) kill(ctx context.Context, dir string) {
	cid := filepath.Base(dir)
	tightUntil := time.Now().Add(m.killRetryDeadline)
	escalateAt := time.Now().Add(m.killEscalateAfter)
	backedOff := false
	var lastErr error

	for attempt := 1; ; attempt++ {
		ok, err := m.killer.kill(cid)
		switch {
		case err != nil:
			lastErr = err
			if attempt == 1 {
				m.logger.Error("kill cgroup failed: denied container was NOT terminated; retrying", "cid", cid, "error", err)
			}
			if time.Now().After(escalateAt) {
				m.abort(fmt.Errorf("kill path unusable: container %s denied but not terminated after %s: %w", cid, m.killEscalateAfter, lastErr))
				return
			}
		case ok:
			m.logger.Info("SIGKILLed container cgroup", "cid", cid, "attempts", attempt)
			return
		default:
			if attempt == 1 {
				m.logger.Error("denied container NOT confirmed terminated: cgroup never found or never populated; retrying", "cid", cid)
			}
		}

		if _, statErr := os.Stat(dir); statErr != nil {
			m.logger.Warn("denied container's bundle was removed before a kill was confirmed", "cid", cid, "attempts", attempt)
			return
		}

		interval := m.killRetryInterval
		if time.Now().After(tightUntil) {
			interval = m.killPendingInterval
			if !backedOff {
				backedOff = true
				m.logger.Error("denied container still NOT terminated; retrying at a slower cadence until its bundle is removed",
					"cid", cid, "attempts", attempt, "interval", interval)
			}
		}

		select {
		case <-ctx.Done():
			m.logger.Error("gave up killing a denied container", "cid", cid, "attempts", attempt, "reason", ctx.Err())
			return
		case <-time.After(interval):
		}
	}
}

// readConfigJSON waits for kata-agent to write the bundle's config.json and
// returns the parsed spec. It gives up only when the bundle directory itself
// goes away or the context ends — the bundle appears when the guest pull STARTS
// (confidential_data_hub::pull_image creates it) and config.json is written
// after add_storages returns, so the gap between the two is a registry fetch,
// not a filesystem race. A deadline shorter than the pull leaves the container
// undecided, which is indistinguishable from admitting it.
//
// A successfully parsed spec is complete: kata-agent builds the OCI spec in
// memory and saves config.json once. A valid spec without annotations is
// therefore an enforcement decision, not a partial write. The host controls
// this file, so delaying that decision based on an optional annotation would
// give a stripped workload an avoidable execution window.
func (m *monitor) readConfigJSON(ctx context.Context, dir string) (*ociSpec, error) {
	path := filepath.Join(dir, "config.json")
	absentUntil := time.Now().Add(m.configReadDeadline)
	var partialUntil time.Time
	backedOff := false
	for {
		spec, err := readOCISpec(path)
		if err == nil && len(spec.Annotations) > 0 {
			return spec, nil
		}
		if err == nil {
			// Parses, but carries no annotations at all. Every CRI stamps
			// several (containerd sets io.kubernetes.cri.* on every container,
			// sandbox included), so an empty map is a spec written but not yet
			// populated, not a container that has none — and judging it reads
			// the pause as a workload with no image reference and kills it,
			// which wedges the whole sandbox.
			//
			// Bounded exactly like a half-written file, and the caller still
			// denies when the budget runs out, so a host that withholds
			// annotations delays a denial rather than earning an admission. A
			// spec with annotations but no CRI keys is a complete policy input
			// and is decided immediately, as before.
			err = errPartialJSON
		}
		if !errors.Is(err, os.ErrNotExist) && !isPartialJSON(err) {
			// Unrecoverable: not a transient race. Return immediately.
			return nil, err
		}

		interval := m.configReadInterval
		switch {
		case isPartialJSON(err):
			// The file is there. kata-agent saves the spec once, so this is a
			// half-finished write or a spec that will never parse — bound it
			// and let the caller deny, rather than wait on it forever.
			if partialUntil.IsZero() {
				partialUntil = time.Now().Add(m.configReadDeadline)
			} else if time.Now().After(partialUntil) {
				return nil, err
			}
		default:
			// Absent. A symlink here resolved to nothing, which is a name the
			// host planted rather than a file kata has yet to write — the open
			// returned ENOENT through the link, so it is dangling. Anything else
			// Lstat can see is a regular config.json that kata created between
			// the read above and this call; loop and read it.
			if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("config.json is a symlink that does not resolve")
			}
			if _, derr := os.Stat(dir); derr != nil {
				return nil, fmt.Errorf("bundle %s went away before config.json appeared: %w", dir, derr)
			}
			if time.Now().After(absentUntil) {
				interval = m.configPendingInterval
				if !backedOff {
					backedOff = true
					m.logger.Info("waiting for config.json; container stays undecided until it appears", "dir", dir)
				}
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// ociSpec is the subset of the OCI Runtime Spec we enforce on: the annotations
// (carrying the image digest) and the process.args (the effective argv). We
// don't pull in opencontainers/runtime-spec — json.Unmarshal silently drops
// everything else.
type ociSpec struct {
	Annotations map[string]string `json:"annotations"`
	Process     *ociProcess       `json:"process"`
	Mounts      []ociMount        `json:"mounts"`
}

// ociProcess is the process block the container runs: the merged image-config +
// pod-spec argv, evaluated against workload argv policy, and the environment it
// starts with, evaluated by name against workload env policy.
type ociProcess struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

// ociMount is one entry of the container's mount table. The baked kata-agent
// policy bounds where a bind's source may be; the destination is a path inside
// the container and is what workload mount policy gates.
type ociMount struct {
	Destination string `json:"destination"`
	Source      string `json:"source"`
}

// bindMountDestinations returns the destinations of the mounts that carry guest
// content in. A source that is not an absolute path names a filesystem type
// (proc, sysfs, tmpfs, devpts, mqueue, cgroup) and carries nothing, so gating it
// would only make an operator restate the OCI base set.
func bindMountDestinations(mounts []ociMount) []string {
	var out []string
	for _, m := range mounts {
		if strings.HasPrefix(m.Source, "/") {
			out = append(out, m.Destination)
		}
	}
	return out
}

// envNames returns the NAME halves of the spec's "NAME=value" environment.
// Values never leave this function: policy matches names, because an allowlist
// is served to every enforcer and values carry secrets.
func envNames(env []string) []string {
	var out []string
	for _, e := range env {
		if name, _, ok := strings.Cut(e, "="); ok {
			out = append(out, name)
		}
	}
	return out
}

func readOCISpec(path string) (*ociSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		// Half-written: kata-agent created the file but hasn't
		// finished writing. Surface a sentinel so the caller knows
		// to retry.
		return nil, errPartialJSON
	}
	var s ociSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		// A SyntaxError on an in-progress write is also a transient
		// state. We don't try to disambiguate (the alternative is to
		// fstat for stable size, which is fragile); we just retry on
		// any unmarshal error too. The outer loop bounds the retry.
		return nil, fmt.Errorf("%w: %v", errPartialJSON, err)
	}
	return &s, nil
}

// errPartialJSON is the sentinel that tells the read loop to retry.
// Wrapped via fmt.Errorf so callers can use errors.Is.
var errPartialJSON = errors.New("partial json")

func isPartialJSON(err error) bool {
	return errors.Is(err, errPartialJSON)
}
