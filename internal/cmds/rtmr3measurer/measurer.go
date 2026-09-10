//go:build linux

// Package rtmr3measurer is the in-VM workload measurer: it scans kata-agent's
// container bundles under /run/kata-containers and extends the guest's runtime
// measurement register with each deployed workload's image digest, binding
// WHICH container ran into the
// guest's attestation — dynamically, for any image, with no baked allowlist.
// It is the measurement-only counterpart to policy-monitor (allowlist
// enforcement); either or both may run.
//
// The extend convention and the exactly-once bookkeeping belong to the
// runtimemeasure package, and a verifier must build on that package. Its
// [runtimemeasure.Journal] keeps the extended set on tmpfs, so a daemon restart
// cannot re-extend the append-only register. Design and rationale:
// docs/kata-guest-base.md "Per-workload RTMR[3] measurement".
package rtmr3measurer

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"

	"github.com/confidential-dot-ai/c8s/internal/kataspec"
)

const (
	watchDir = "/run/kata-containers"
	// statePath is the measured-digest journal. /run is tmpfs: it survives a
	// process restart and is wiped with the VM — the same lifetime as
	// RTMR[3] itself. The /run/c8s dir is created by tmpfiles.d/c8s.conf.
	statePath = "/run/c8s/rtmr3-measured"

	scanInterval     = 1 * time.Second
	readDirWarnEvery = 60 // scans between repeated cannot-read-watch-dir warns
)

type ociSpec struct {
	Annotations map[string]string `json:"annotations"`
}

// measurer holds the scan state. All fields are touched only from the single
// run loop (no lock).
type measurer struct {
	logger    *slog.Logger
	watchDir  string
	statePath string

	// reg is the guest's RTMR[3]; tests inject a temp-file register. journal
	// holds the correctness-critical dedup — digests already extended, keyed
	// on digest (not cid) so restarts and replicas of one image extend
	// exactly once.
	reg     runtimemeasure.Register
	journal *runtimemeasure.Journal

	// seenCids: cids already decided, so config.json isn't re-read every
	// scan; pruned as container dirs disappear.
	seenCids map[string]struct{}

	configReadDeadline time.Duration
	configReadInterval time.Duration
	readDirFails       int
}

func newMeasurer(logger *slog.Logger) *measurer {
	return &measurer{
		logger:             logger,
		watchDir:           watchDir,
		statePath:          statePath,
		seenCids:           map[string]struct{}{},
		configReadDeadline: 2 * time.Second,
		configReadInterval: 50 * time.Millisecond,
	}
}

// Run is the cobra-driven entry point (mirrors policymonitor.Run's shape).
func Run(_ []string) error {
	m := newMeasurer(slog.Default())
	m.logger.Info("rtmr3-measurer starting",
		"watch_dir", m.watchDir, "state", m.statePath)
	if err := m.open(); err != nil {
		return err
	}
	// Poll, don't inotify: kata-agent mounts /run/kata-containers after this
	// daemon starts, so an early inotify watch binds the pre-mount inode and
	// never fires. See docs/kata-guest-base.md — rtmr3-measurer.
	for {
		m.scanOnce()
		time.Sleep(scanInterval)
	}
}

// open resolves RTMR[3] and loads the journal over it. The kata guest VM's
// register starts at zero — nothing seeds it before this daemon runs — so the
// unseeded OpenJournal is the right one.
//
// A soft anomaly (a skipped malformed line, an unreadable register, a register
// carrying extends the journal cannot account for) comes back alongside a
// usable journal: log it and keep measuring, because giving up would leave the
// guest measuring nothing for the rest of the boot. Only a nil journal is
// fatal.
func (m *measurer) open() error {
	if m.reg == nil {
		reg, err := runtimemeasure.Open(teetypes.PlatformTDX)
		if err != nil {
			return err
		}
		m.reg = reg
	}
	journal, err := runtimemeasure.OpenJournal(m.statePath, m.reg)
	if journal == nil {
		return err
	}
	m.journal = journal
	switch {
	case errors.Is(err, runtimemeasure.ErrRegisterDiverged):
		m.logger.Error("RTMR[3] does not match the measured-digest log; this VM's workload attestation will not verify",
			"error", err)
	case err != nil:
		m.logger.Warn("measured-digest log anomaly; measuring continues", "error", err)
	}
	if n := len(journal.Digests()); n > 0 {
		m.logger.Info("restart: reloaded measured-digest log", "count", n)
	}
	return nil
}

func (m *measurer) scanOnce() {
	entries, err := os.ReadDir(m.watchDir)
	if err != nil {
		// Throttled: a permanently unreadable watch dir must not spin silently.
		if m.readDirFails%readDirWarnEvery == 0 {
			m.logger.Warn("cannot read watch dir",
				"dir", m.watchDir, "error", err, "consecutive_failures", m.readDirFails+1)
		}
		m.readDirFails++
		return
	}
	m.readDirFails = 0
	present := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		present[e.Name()] = struct{}{}
		m.handle(filepath.Join(m.watchDir, e.Name()))
	}
	// Prune decided cids whose dirs are gone (container removed) so the map
	// cannot grow unbounded in a container-churning guest. Cids are never
	// reused, and the durable dedup is the journal, which mirrors the
	// register.
	for cid := range m.seenCids {
		if _, ok := present[cid]; !ok {
			delete(m.seenCids, cid)
		}
	}
}

func (m *measurer) handle(dir string) {
	cid := filepath.Base(dir)
	if !kataspec.ValidContainerID(cid) {
		return // not a container id the baked kata-agent policy admits
	}
	if _, done := m.seenCids[cid]; done {
		return
	}
	spec, err := m.readConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		return // config.json not written yet; retry next scan (do NOT mark seen)
	}
	m.seenCids[cid] = struct{}{} // decided this cid — don't re-read it every scan

	// The pause/sandbox container is the measured rootfs, not a workload,
	// and carries no image-name annotation.
	if kataspec.IsSandbox(spec.Annotations) {
		return
	}
	digest, ok := kataspec.PullDigest(spec.Annotations)
	if !ok {
		// Measure-only: unlike policy-monitor we do not kill; an unpinned
		// image simply isn't reflected in RTMR[3], so a relying party
		// rejects its quote there.
		m.logger.Warn("no image digest annotation; not measurable (pin the image by digest)", "cid", cid)
		return
	}
	switch extended, err := m.journal.MeasureOnce(digest); {
	case err != nil:
		m.logger.Error("extend RTMR[3] failed", "cid", cid, "digest", digest, "error", err)
	case extended:
		m.logger.Info("measured workload into RTMR[3]", "cid", cid, "digest", digest)
	default:
		m.logger.Info("image already measured into RTMR[3]; skipping duplicate (restart or replica)",
			"cid", cid, "digest", digest)
	}
}

// readConfig reads config.json with a short retry, since a scan can catch the
// <cid> dir a moment before kata-agent has written the file.
func (m *measurer) readConfig(path string) (*ociSpec, error) {
	deadline := time.Now().Add(m.configReadDeadline)
	var lastErr error
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			var s ociSpec
			if jerr := json.Unmarshal(b, &s); jerr == nil {
				return &s, nil
			} else {
				lastErr = jerr
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(m.configReadInterval)
	}
}
