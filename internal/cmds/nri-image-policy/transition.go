package nriimagepolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
)

// Enrollment retry parameters at startup. Declared as vars so tests can shrink
// the backoff.
var (
	enrollMaxRetries   = 5
	enrollInitialDelay = 2 * time.Second
)

// errNoAppliedPolicy is enrollment before the first verified state landed: the
// enrollment names the policy this node applies, so there is nothing to say
// yet.
var errNoAppliedPolicy = errors.New("no CDS-verified policy applied yet")

// errUnpinnedAuthority is a state signed by an authority other than the one
// allowlist.pull.authority pins. It is a decision about trust, not a transient
// failure.
var errUnpinnedAuthority = errors.New("the state authority is not the pinned one")

// bootIdentity is this process's participant identity: a fresh Ed25519 key per
// start, whose public half names the boot.
//
// The key is generated, not derived: every input a host process can derive
// from (boot_id, node name, machine id) is readable by the untrusted host, so
// a derived key would authenticate nothing. It is held only in memory, so a
// plugin restart is a new boot that re-enrols, and CDS keeps the old boot's
// obligations outstanding until it completes them.
//
// FOLLOW-UP the design requires: bind this key to the CVM boot and to the
// node's attested identity — the same identity startSandboxDigests serves to
// CDS over mutually-attested RA-TLS — so an enrollment proves which hardware
// boot it came from. Until then the boot key is an unauthenticated claim that
// CDS records on first use.
type bootIdentity struct {
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
	id       string
	nodeName string
}

// newBootIdentity generates the boot key. nodeName falls back to the hostname;
// it is informational in the log, the key is the identity.
func newBootIdentity(nodeName string) (bootIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return bootIdentity{}, fmt.Errorf("generate boot key: %w", err)
	}
	if nodeName == "" {
		nodeName, err = os.Hostname()
		if err != nil {
			return bootIdentity{}, fmt.Errorf("node name: %w", err)
		}
	}
	return bootIdentity{private: priv, public: pub, id: policystate.BootID(pub), nodeName: nodeName}, nil
}

// updateState is what this boot has done about the one update CDS has
// outstanding. V1 serializes updates, so one value is the whole record and a
// new version resets it — which is also what keeps target cached for exactly
// one update.
type updateState struct {
	version      uint64
	targetDigest string
	target       *allowlist.Allowlist
	acked        bool
	applied      bool
	completed    bool
}

// transitionSyncer follows the CDS signed state and moves this node through
// the barrier, the switch and the completion of one update
// (docs/allowlist-and-capabilities.md, "Enforcer updates"). One goroutine
// runs it; the only thing that reaches in from another is the drain wake-up,
// which is a channel poke.
type transitionSyncer struct {
	client   policystateclient.Client
	store    *policyStore
	live     *liveInstances
	boot     bootIdentity
	pinned   string // authority fingerprint from config; empty learns one
	interval time.Duration
	timeout  time.Duration
	logger   *slog.Logger

	drainCh   chan struct{}
	authority string
	enrolled  bool
	cur       updateState
}

type transitionSyncerArgs struct {
	client   policystateclient.Client
	store    *policyStore
	live     *liveInstances
	boot     bootIdentity
	pinned   string
	interval time.Duration
	timeout  time.Duration
	logger   *slog.Logger
}

func newTransitionSyncer(args transitionSyncerArgs) *transitionSyncer {
	s := &transitionSyncer{
		client:   args.client,
		store:    args.store,
		live:     args.live,
		boot:     args.boot,
		pinned:   args.pinned,
		interval: args.interval,
		timeout:  args.timeout,
		logger:   args.logger,
		drainCh:  make(chan struct{}, 1),
	}
	// RemoveContainer runs on the NRI hot path: it must not block on CDS, so
	// the last pending instance only wakes the loop.
	args.live.setOnDrained(func() {
		select {
		case s.drainCh <- struct{}{}:
		default:
		}
	})
	return s
}

// Run syncs once, enrols, then follows the state until ctx is cancelled.
//
// The first sync comes before enrollment because an enrollment names the
// policy this node applies, and that is only known once a signed state has
// been read. A failed enrollment costs acknowledgements, never admission: the
// node keeps enforcing what it has applied.
func (s *transitionSyncer) Run(ctx context.Context) {
	s.logger.Info("following CDS policy state", "boot_id", s.boot.id, "node", s.boot.nodeName)
	_ = s.syncState(ctx)
	s.enrollWithBackoff(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.enroll(ctx)
			_ = s.syncState(ctx)
		case <-s.drainCh:
			s.completeIfDrained(ctx)
		}
	}
}

// syncState fetches the signed state, verifies it and acts on the phase it
// reports. Anything unverifiable leaves the applied policy alone: a withheld
// or forged state degrades the node to stale, never to open.
//
// The error it returns is the one that kept the node from enforcing what the
// state names, which is what the cold-start pull retries. Acknowledgements and
// completions are only logged: the next poll sends them again.
func (s *transitionSyncer) syncState(ctx context.Context) error {
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	stmt, err := s.state(reqCtx)
	if err != nil {
		s.logger.Warn("policy state fetch failed; keeping the applied policy", "error", err)
		return err
	}

	var applyErr error
	switch {
	case stmt.Update == nil:
		s.forget()
		applyErr = s.applyPolicy(reqCtx, stmt.ActiveVersion, stmt.ActiveDigest)
	case !stmt.Update.Switched:
		s.track(*stmt.Update)
		// The source policy is still the one in force, and the pending set is
		// diffed against it: acknowledging a barrier over a stale document
		// would count the wrong instances.
		if applyErr = s.applyPolicy(reqCtx, stmt.ActiveVersion, stmt.ActiveDigest); applyErr == nil {
			s.ackBarrier(reqCtx, *stmt.Update)
		}
	default:
		s.track(*stmt.Update)
		applyErr = s.applyTarget(reqCtx, *stmt.Update)
	}
	if applyErr != nil {
		s.logger.Warn("cannot apply the policy the state names; keeping the applied one", "error", applyErr)
	}
	s.completeIfDrained(ctx)
	return applyErr
}

// state fetches the signed statement, checks the signature against the key it
// carries and decides whether that authority may drive this node.
func (s *transitionSyncer) state(ctx context.Context) (policystate.State, error) {
	signed, err := s.client.State(ctx)
	if err != nil {
		return policystate.State{}, err
	}
	if err := policystate.VerifySignedState(signed); err != nil {
		return policystate.State{}, err
	}
	if err := s.acceptAuthority(signed.Statement.Authority); err != nil {
		return policystate.State{}, err
	}
	return signed.Statement, nil
}

// acceptAuthority settles whether to act on a statement that already verified
// under the key it carries. A fingerprint pinned in config is the trust
// anchor; without one the first statement over the attested pull channel
// teaches the node its authority, and a change is a CDS restart under a new
// key — accepted only because the statement verifies under it, and treated as
// a new deployment this boot must enrol with again.
func (s *transitionSyncer) acceptAuthority(authority string) error {
	switch {
	case s.pinned != "":
		if authority != s.pinned {
			return fmt.Errorf("%w: CDS signs as %s, config pins %s", errUnpinnedAuthority, authority, s.pinned)
		}
	case s.authority == "":
		s.logger.Info("learned the CDS authority over the attested pull channel", "authority", authority)
	case authority != s.authority:
		s.logger.Warn("the CDS authority changed; re-enrolling under it",
			"authority", authority, "previous", s.authority)
		s.cur = updateState{}
		s.enrolled = false
	}
	s.authority = authority
	return nil
}

// applyPolicy installs the policy object named by digest, unless it is already
// the applied one. The client re-hashes the bytes it serves, so a document
// that is not the one the state names never reaches the parser.
func (s *transitionSyncer) applyPolicy(ctx context.Context, version uint64, digest string) error {
	if cur := s.store.current(); cur != nil && cur.digest == digest {
		return nil
	}
	doc, err := s.policy(ctx, digest)
	if err != nil {
		return err
	}
	s.store.apply(doc, version, digest)
	s.logger.Info("applied the active policy", "version", version, "digest", digest, "workloads", len(doc.Workloads))
	return nil
}

// ackBarrier answers an outstanding update that has not switched: it closes
// the admission barrier, marks the live instances the target no longer admits
// pending, and acknowledges with their count. Nothing here widens admission —
// the node goes on enforcing the source policy.
func (s *transitionSyncer) ackBarrier(ctx context.Context, u policystate.Update) {
	if s.cur.acked {
		return
	}
	if !s.enrolled {
		s.logger.Info("not enrolled with CDS; cannot acknowledge the outstanding update", "version", u.Version)
		return
	}
	target, err := s.target(ctx, u.TargetDigest)
	if err != nil {
		s.logger.Warn("cannot fetch the update's target policy", "digest", u.TargetDigest, "error", err)
		return
	}

	snap, release := s.store.halt()
	pending := s.live.markPending(removedKeys(snap.doc, target))
	release()

	ack := policystate.Ack{
		Protocol:     policystate.Protocol,
		BootID:       s.boot.id,
		Version:      u.Version,
		TargetDigest: u.TargetDigest,
		Retired:      uint64(len(pending)),
	}
	if err := s.client.Ack(ctx, s.boot.private, ack); err != nil {
		s.logger.Warn("acknowledging the update failed; retrying", "version", u.Version, "error", err)
		return
	}
	s.cur.acked = true
	s.logger.Info("acknowledged an update barrier", "version", u.Version, "retired", len(pending))
}

// applyTarget installs the target policy once the coordinator has switched to
// it. This is the only step that widens what may run.
//
// A boot that never acknowledged marks its own instances pending first: it
// joined after the participant set was frozen, so nobody counted them, and
// widening admission without marking them would turn them into violations the
// next Synchronize stops. The marking and the swap share one barrier span, or
// a create decided under the source policy in between would run unrecorded.
func (s *transitionSyncer) applyTarget(ctx context.Context, u policystate.Update) error {
	if s.cur.applied {
		return nil
	}
	target, err := s.target(ctx, u.TargetDigest)
	if err != nil {
		return err
	}

	snap, release := s.store.halt()
	if !s.cur.acked {
		s.live.markPending(removedKeys(snap.doc, target))
	}
	s.store.applyHalted(target, u.Version, u.TargetDigest)
	release()

	s.cur.applied = true
	s.logger.Info("applied the switched target policy",
		"version", u.Version, "digest", u.TargetDigest, "pending_instances", s.live.pendingCount())
	return nil
}

// completeIfDrained tells CDS the target is applied and nothing on this node
// still holds a permission only the source granted. It is also the answer when
// the update removed nothing here: saying so at once is what keeps the fleet's
// update from waiting on an idle node.
func (s *transitionSyncer) completeIfDrained(ctx context.Context) {
	if s.cur.version == 0 || !s.cur.applied || s.cur.completed || !s.enrolled {
		return
	}
	if s.live.pendingCount() > 0 {
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	completion := policystate.Completion{
		Protocol:     policystate.Protocol,
		BootID:       s.boot.id,
		Version:      s.cur.version,
		TargetDigest: s.cur.targetDigest,
	}
	if err := s.client.Complete(reqCtx, s.boot.private, completion); err != nil {
		s.logger.Warn("reporting completion failed; retrying", "version", s.cur.version, "error", err)
		return
	}
	s.cur.completed = true
	s.logger.Info("reported update completion", "version", s.cur.version)
}

// track resets the per-update record when CDS names a different version.
func (s *transitionSyncer) track(u policystate.Update) {
	if s.cur.version != u.Version {
		s.cur = updateState{version: u.Version, targetDigest: u.TargetDigest}
	}
}

// forget drops the record and the pending set once CDS reports no update
// outstanding: the completion that ended it also ended the pending
// permissions.
func (s *transitionSyncer) forget() {
	if s.cur.version == 0 {
		return
	}
	s.cur = updateState{}
	s.live.clearPending()
}

// target returns the update's target document, fetched once per update: track
// clears the cache when CDS names a different version.
func (s *transitionSyncer) target(ctx context.Context, digest string) (*allowlist.Allowlist, error) {
	if s.cur.target != nil {
		return s.cur.target, nil
	}
	doc, err := s.policy(ctx, digest)
	if err != nil {
		return nil, err
	}
	s.cur.target = doc
	return doc, nil
}

// policy fetches one policy object by digest. The client re-hashes the served
// bytes against the digest they were asked for.
func (s *transitionSyncer) policy(ctx context.Context, digest string) (*allowlist.Allowlist, error) {
	body, err := s.client.Policy(ctx, digest)
	if err != nil {
		return nil, err
	}
	return allowlist.ParseServedJSON(body)
}

// enrollWithBackoff announces this boot to CDS, retrying a bounded number of
// times before handing the retry to the loop's own cadence. A 409 ends the
// backoff at once: CDS holds new participants outside the protocol until the
// outstanding update completes, which no amount of retrying shortens.
func (s *transitionSyncer) enrollWithBackoff(ctx context.Context) {
	delay := enrollInitialDelay
	for attempt := 1; attempt <= enrollMaxRetries; attempt++ {
		err := s.enroll(ctx)
		if err == nil || policystateclient.IsStatus(err, http.StatusConflict) || attempt == enrollMaxRetries {
			return
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		delay *= 2
	}
}

// enroll posts one enrollment, naming the policy this node applies. It enrols
// only against a CDS-verified policy: enrolling with a digest no state named
// would make CDS record a starting point no object backs.
func (s *transitionSyncer) enroll(ctx context.Context) error {
	if s.enrolled {
		return nil
	}
	snap := s.store.current()
	if snap == nil || snap.digest == "" {
		s.logger.Info("no CDS-verified policy applied yet; deferring enrollment")
		return errNoAppliedPolicy
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	err := s.client.Enroll(reqCtx, s.boot.private, policystate.Enrollment{
		Protocol:      policystate.Protocol,
		BootID:        s.boot.id,
		Name:          s.boot.nodeName,
		BootKey:       policystate.EncodeBootKey(s.boot.public),
		AppliedDigest: snap.digest,
	})
	switch {
	case policystateclient.IsStatus(err, http.StatusConflict):
		s.logger.Info("CDS holds new participants outside the protocol until the outstanding update completes; retrying",
			"boot_id", s.boot.id)
		return err
	case err != nil:
		s.logger.Warn("enrollment failed; the node keeps enforcing its applied policy but cannot acknowledge updates",
			"boot_id", s.boot.id, "error", err)
		return err
	}
	s.enrolled = true
	s.logger.Info("enrolled with CDS",
		"boot_id", s.boot.id, "node", s.boot.nodeName, "applied_digest", snap.digest)
	return nil
}

// removedKeys names the rules applied grants and updated does not: the set an
// instance must have been admitted under to still hold a source-only
// permission.
func removedKeys(applied, updated *allowlist.Allowlist) map[string]struct{} {
	removed := allowlist.Removed(applied, updated)
	out := make(map[string]struct{}, len(removed))
	for _, rule := range removed {
		out[allowlist.RuleKey(rule)] = struct{}{}
	}
	return out
}

// admittedRuleKey names the rule of snap that admits this container, which is
// what makes the instance attributable to a permission a later policy can
// remove. Empty when no rule admits it: always_allow, an exempt namespace and
// audit mode all let containers run that the served document does not grant.
func (p *plugin) admittedRuleKey(snap *policySnapshot, ctr *api.Container, digest string) string {
	if snap == nil || digest == "" {
		return ""
	}
	match, ok := snap.index.MatchContainer(allowlist.RunningContainer{
		Digest: digest,
		Argv:   ctr.GetArgs(),
		Env:    containerEnv(ctr),
	})
	if !ok {
		return ""
	}
	return allowlist.RuleKey(allowlist.Rule(match))
}
