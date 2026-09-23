package nriimagepolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/policystateclient"
)

// argvAllowlist builds a one-workload, one-container document: the unit an
// update removes. An empty argv means "any command".
//
// The document is round-tripped through the served form so it is normalized
// exactly as the copy a node fetches from CDS. Rule keys are taken over the
// normalized document, so an un-normalized fixture would name rules no
// enforcer ever sees.
func argvAllowlist(name, digest string, argv []string) *allowlist.Allowlist {
	command := allowlist.ArgvPolicy{Policy: allowlist.PolicyAny}
	if len(argv) > 0 {
		command = allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: argv}
	}
	al := &allowlist.Allowlist{
		Schema: allowlist.Schema,
		Workloads: map[string]allowlist.Workload{
			name: {Containers: []allowlist.Container{{
				Digest:  mustDigestOrPanic(digest),
				Command: command,
				Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			}}},
		},
	}
	canonical, err := al.Canonical()
	if err != nil {
		panic(err)
	}
	normalized, err := allowlist.ParseServedJSON(canonical)
	if err != nil {
		panic(err)
	}
	return normalized
}

// ruleKeyOf is the key of the single rule argvAllowlist builds, the value
// admission tags an instance with.
func ruleKeyOf(t *testing.T, al *allowlist.Allowlist) string {
	t.Helper()
	rules := allowlist.Rules(al)
	if len(rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(rules))
	}
	return allowlist.RuleKey(rules[0])
}

// policyDigest names a document the way CDS does: the content digest of its
// canonical bytes.
func policyDigest(t *testing.T, al *allowlist.Allowlist) string {
	t.Helper()
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	return policystate.ContentDigest(canonical)
}

// pullingConfig is a plugin configured to follow CDS, which is what makes
// update bookkeeping live.
func pullingConfig() *config {
	return &config{
		Policy:    policyConfig{Mode: ModeFailClosed},
		Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds.example"}},
	}
}

// syncerFixture is a node following one fake CDS.
type syncerFixture struct {
	cds    *fakeCDS
	store  *policyStore
	live   *liveInstances
	syncer *transitionSyncer
}

// newSyncerFixture builds a node that learns its authority from the first
// verified state.
func newSyncerFixture(t *testing.T) *syncerFixture {
	t.Helper()
	return newFixture(t, false)
}

// newPinnedFixture builds a node whose config pins the fake's current
// authority.
func newPinnedFixture(t *testing.T) *syncerFixture {
	t.Helper()
	return newFixture(t, true)
}

func newFixture(t *testing.T, pin bool) *syncerFixture {
	t.Helper()
	cds := newFakeCDS(t)
	srv := cds.serve()
	store := newPolicyStore(nil)
	live := newLiveInstances()
	boot, err := newBootIdentity("node-under-test")
	if err != nil {
		t.Fatalf("newBootIdentity: %v", err)
	}
	pinned := ""
	if pin {
		pinned = cds.authority
	}
	syncer := newTransitionSyncer(transitionSyncerArgs{
		client:   policystateclient.NewWithHTTP(srv.URL, srv.Client()),
		store:    store,
		live:     live,
		boot:     boot,
		pinned:   pinned,
		interval: time.Hour,
		timeout:  5 * time.Second,
		logger:   discardLogger(),
	})
	return &syncerFixture{cds: cds, store: store, live: live, syncer: syncer}
}

// sync runs one pass of the loop body.
func (f *syncerFixture) sync(t *testing.T) {
	t.Helper()
	_ = f.syncer.syncState(context.Background())
}

// enroll brings the node into the participant set, which acknowledging
// requires.
func (f *syncerFixture) enroll(t *testing.T) {
	t.Helper()
	if err := f.syncer.enroll(context.Background()); err != nil {
		t.Fatalf("enroll: %v", err)
	}
}

func TestSyncAppliesTheVerifiedActivePolicy(t *testing.T) {
	f := newSyncerFixture(t)
	digest := f.cds.seed(argvAllowlist("app", pushDigestA, nil))

	f.sync(t)

	snap := f.store.current()
	if snap.digest != digest || snap.version != 1 {
		t.Fatalf("applied snapshot = (%s, %d), want (%s, 1)", snap.digest, snap.version, digest)
	}
	if !snap.index.AdmitsDigest(pushDigestA) {
		t.Fatal("the applied policy does not admit the active policy's digest")
	}
	if f.syncer.authority != f.cds.authority {
		t.Fatalf("learned authority = %s, want %s", f.syncer.authority, f.cds.authority)
	}
}

// TestSyncFollowsAnAuthorityChangeOnlyWhenItVerifies covers the three ways the
// authority in a statement can differ from the one a node is following: a CDS
// that restarted under a new key (followed, and re-enrolled with), a statement
// naming an authority its signature does not back (refused), and a new key
// where config pinned the old one (refused).
func TestSyncFollowsAnAuthorityChangeOnlyWhenItVerifies(t *testing.T) {
	otherAuthority := func(t *testing.T) string {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		fingerprint, err := policystate.AuthorityFingerprint(pub)
		if err != nil {
			t.Fatalf("AuthorityFingerprint: %v", err)
		}
		return fingerprint
	}

	tests := []struct {
		name        string
		pinned      bool
		change      func(t *testing.T, f *syncerFixture)
		wantApplied bool
	}{
		{
			name:        "CDS restarted under a new key",
			change:      func(_ *testing.T, f *syncerFixture) { f.cds.rekey() },
			wantApplied: true,
		},
		{
			name:        "the same authority under a pin",
			pinned:      true,
			change:      func(_ *testing.T, f *syncerFixture) {},
			wantApplied: true,
		},
		{
			name:        "a new key where config pins the old one",
			pinned:      true,
			change:      func(_ *testing.T, f *syncerFixture) { f.cds.rekey() },
			wantApplied: false,
		},
		{
			name:        "an authority the signature does not back",
			change:      func(t *testing.T, f *syncerFixture) { f.cds.forgedAuthority = otherAuthority(t) },
			wantApplied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSyncerFixture(t)
			if tt.pinned {
				f = newPinnedFixture(t)
			}
			first := f.cds.seed(argvAllowlist("app", pushDigestA, nil))
			f.sync(t)
			f.enroll(t)

			tt.change(t, f)
			second := f.cds.seed(argvAllowlist("app", pushDigestB, nil))
			f.sync(t)

			want := first
			if tt.wantApplied {
				want = second
			}
			if got := f.store.current().digest; got != want {
				t.Fatalf("applied digest = %s, want %s", got, want)
			}
		})
	}
}

// A followed authority change is a different deployment: the node must enrol
// with it rather than go on acknowledging to a CDS that never heard of it.
func TestSyncReEnrolsAfterAnAuthorityChange(t *testing.T) {
	f := newSyncerFixture(t)
	f.cds.seed(argvAllowlist("app", pushDigestA, nil))
	f.sync(t)
	f.enroll(t)

	f.cds.rekey()
	f.cds.seed(argvAllowlist("app", pushDigestB, nil))
	f.sync(t)

	if f.syncer.enrolled {
		t.Fatal("the node still counts itself enrolled with an authority that restarted")
	}
	f.enroll(t)
	if enrollments, _, _ := f.cds.recorded(); len(enrollments) != 2 {
		t.Fatalf("len(enrollments) = %d, want 2", len(enrollments))
	}
}

func TestEnrollmentNamesTheAppliedPolicy(t *testing.T) {
	f := newSyncerFixture(t)
	digest := f.cds.seed(argvAllowlist("app", pushDigestA, nil))

	if err := f.syncer.enroll(context.Background()); err == nil {
		t.Fatal("enrolled before any CDS-verified policy was applied")
	}

	f.sync(t)
	f.enroll(t)

	enrollments, _, _ := f.cds.recorded()
	if len(enrollments) != 1 {
		t.Fatalf("len(enrollments) = %d, want 1", len(enrollments))
	}
	got := enrollments[0]
	if got.BootID != f.syncer.boot.id || got.AppliedDigest != digest {
		t.Fatalf("enrollment = (%s, %s), want (%s, %s)", got.BootID, got.AppliedDigest, f.syncer.boot.id, digest)
	}
}

// CDS holds a joining node outside the protocol while an update is
// outstanding. The node keeps enforcing and tries again on the next poll.
func TestEnrollmentConflictIsRetried(t *testing.T) {
	f := newSyncerFixture(t)
	f.cds.seed(argvAllowlist("app", pushDigestA, nil))
	f.sync(t)

	f.cds.enrollStatus = http.StatusConflict
	err := f.syncer.enroll(context.Background())
	if !policystateclient.IsStatus(err, http.StatusConflict) {
		t.Fatalf("enroll during an update = %v, want a 409", err)
	}
	if f.syncer.enrolled {
		t.Fatal("a refused enrollment left the node counting itself enrolled")
	}

	f.cds.enrollStatus = 0
	f.enroll(t)
	if enrollments, _, _ := f.cds.recorded(); len(enrollments) != 1 {
		t.Fatalf("len(enrollments) = %d, want the retry to land", len(enrollments))
	}
}

func TestOutstandingUpdateMarksPendingAndAcks(t *testing.T) {
	source := argvAllowlist("app", pushDigestA, nil)
	// Narrowing the command keeps the digest and changes the rule, so the
	// running instance holds a permission the target does not grant even
	// though its image is still allowed.
	target := argvAllowlist("app", pushDigestA, []string{"/bin/app", "--safe"})

	tests := []struct {
		name        string
		liveRules   []string // rule key per live container, in ID order
		wantPending []string
	}{
		{name: "nothing live", wantPending: nil},
		{name: "instance of the removed rule", liveRules: []string{ruleKeyOf(t, source)}, wantPending: []string{"ctr-0"}},
		{name: "instance of a rule the target keeps", liveRules: []string{ruleKeyOf(t, target)}, wantPending: nil},
		{
			name:        "always_allow instance is never pending",
			liveRules:   []string{"", ruleKeyOf(t, source)},
			wantPending: []string{"ctr-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSyncerFixture(t)
			sourceDigest := f.cds.seed(source)
			f.sync(t)
			f.enroll(t)
			for i, key := range tt.liveRules {
				f.live.admit("ctr-"+strconv.Itoa(i), "sandbox", key)
			}

			targetDigest := f.cds.publish(target)
			f.sync(t)

			_, acks, _ := f.cds.recorded()
			if len(acks) != 1 {
				t.Fatalf("len(acks) = %d, want 1", len(acks))
			}
			got := acks[0]
			if got.Retired != uint64(len(tt.wantPending)) {
				t.Fatalf("ack retired = %d, want %d", got.Retired, len(tt.wantPending))
			}
			if got.Version != 2 || got.TargetDigest != targetDigest {
				t.Fatalf("ack names (%d, %s), want (2, %s)", got.Version, got.TargetDigest, targetDigest)
			}
			for _, id := range tt.wantPending {
				if !f.live.isPending(id) {
					t.Fatalf("container %s was acknowledged as retired but is not pending", id)
				}
			}
			// An unswitched update authorizes nothing: the node still enforces
			// the source policy.
			if got := f.store.current().digest; got != sourceDigest {
				t.Fatalf("applied digest = %s, want the source %s", got, sourceDigest)
			}
		})
	}
}

func TestBarrierDoesNotAckBeforeEnrollment(t *testing.T) {
	f := newSyncerFixture(t)
	f.cds.seed(argvAllowlist("app", pushDigestA, nil))
	f.sync(t)

	f.cds.publish(argvAllowlist("app", pushDigestA, []string{"/bin/app"}))
	f.sync(t)

	if _, acks, _ := f.cds.recorded(); len(acks) != 0 {
		t.Fatalf("len(acks) = %d, want 0 before enrollment", len(acks))
	}
}

func TestSwitchAppliesTheTargetAndCompletesAtOnce(t *testing.T) {
	f := newSyncerFixture(t)
	f.cds.seed(argvAllowlist("app", pushDigestA, nil))
	f.sync(t)
	f.enroll(t)

	targetDigest := f.cds.publish(argvAllowlist("app", pushDigestB, nil))
	f.sync(t)
	f.cds.switchUpdate()
	f.sync(t)

	snap := f.store.current()
	if snap.digest != targetDigest {
		t.Fatalf("applied digest = %s, want the switched target %s", snap.digest, targetDigest)
	}
	if !snap.index.AdmitsDigest(pushDigestB) {
		t.Fatal("the switched policy does not admit the target digest")
	}
	// Nothing was pending here, so the node has nothing to drain and says so at
	// once rather than holding the fleet's update open.
	_, _, completions := f.cds.recorded()
	if len(completions) != 1 {
		t.Fatalf("len(completions) = %d, want 1", len(completions))
	}
	if completions[0].Version != 2 || completions[0].TargetDigest != targetDigest {
		t.Fatalf("completion = (%d, %s), want (2, %s)", completions[0].Version, completions[0].TargetDigest, targetDigest)
	}
}

func TestCompletionWaitsForTheLastPendingInstance(t *testing.T) {
	source := argvAllowlist("app", pushDigestA, nil)
	f := newSyncerFixture(t)
	f.cds.seed(source)
	f.sync(t)
	f.enroll(t)
	f.live.admit("ctr-a", "sandbox", ruleKeyOf(t, source))
	f.live.admit("ctr-b", "sandbox", ruleKeyOf(t, source))

	f.cds.publish(argvAllowlist("app", pushDigestB, nil))
	f.sync(t)
	f.cds.switchUpdate()
	f.sync(t)

	if _, _, completions := f.cds.recorded(); len(completions) != 0 {
		t.Fatalf("len(completions) = %d, want 0 with two instances pending", len(completions))
	}

	f.live.remove("ctr-a")
	f.drainWake(t, false)
	f.live.remove("ctr-b")
	f.drainWake(t, true)

	if _, _, completions := f.cds.recorded(); len(completions) != 1 {
		t.Fatalf("len(completions) = %d, want 1 once the last pending instance is gone", len(completions))
	}

	// A completed update clears the record rather than leaving the node
	// carrying a permission nothing holds.
	f.cds.completeUpdate()
	f.sync(t)
	if f.live.pendingCount() != 0 || f.syncer.cur.version != 0 {
		t.Fatalf("pending = %d, update = %d, want 0 and 0 after completion", f.live.pendingCount(), f.syncer.cur.version)
	}
}

// drainWake drains the syncer's wake-up channel and runs the completion the
// loop would run, asserting whether the last removal woke it.
func (f *syncerFixture) drainWake(t *testing.T, want bool) {
	t.Helper()
	select {
	case <-f.syncer.drainCh:
		if !want {
			t.Fatal("a removal that left instances pending woke the completion")
		}
		f.syncer.completeIfDrained(context.Background())
	default:
		if want {
			t.Fatal("removing the last pending instance did not wake the completion")
		}
	}
}

// A node that joined after the participant set was frozen never acknowledged,
// so nobody counted its instances. It must mark its own before the target
// widens admission, or the next Synchronize stops them.
func TestLateJoinerMarksItsOwnInstancesAtTheSwitch(t *testing.T) {
	source := argvAllowlist("app", pushDigestA, nil)
	f := newSyncerFixture(t)
	f.cds.seed(source)
	f.sync(t)
	f.enroll(t)
	f.live.admit("ctr-late", "sandbox", ruleKeyOf(t, source))

	targetDigest := f.cds.publish(argvAllowlist("app", pushDigestB, nil))
	f.cds.switchUpdate()
	f.sync(t)

	if got := f.store.current().digest; got != targetDigest {
		t.Fatalf("applied digest = %s, want the switched target %s", got, targetDigest)
	}
	if !f.live.isPending("ctr-late") {
		t.Fatal("a late joiner left its retired instance unpending, so the next sync would kill it")
	}
	if _, _, completions := f.cds.recorded(); len(completions) != 0 {
		t.Fatalf("len(completions) = %d, want 0 while an instance is pending", len(completions))
	}
}

// A create between the acknowledgement and the switch is still admitted by the
// source policy. It must join the pending set, or the switch would turn it
// into a violation the enforcer stops.
func TestInstanceCreatedBeforeTheSwitchIsPending(t *testing.T) {
	source := argvAllowlist("app", pushDigestA, nil)
	f := newSyncerFixture(t)
	f.cds.seed(source)
	f.sync(t)
	f.enroll(t)

	f.cds.publish(argvAllowlist("app", pushDigestB, nil))
	f.sync(t)

	f.live.admit("ctr-after-ack", "sandbox", ruleKeyOf(t, source))
	if !f.live.isPending("ctr-after-ack") {
		t.Fatal("a container created under the removed rule after the ack is not pending")
	}

	f.cds.switchUpdate()
	f.sync(t)
	if _, _, completions := f.cds.recorded(); len(completions) != 0 {
		t.Fatalf("len(completions) = %d, want 0 while the late instance is pending", len(completions))
	}
}

func TestRemoveContainerClearsTheLiveInstance(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.live = newLiveInstances()
	p.live.admit("ctr-1", "sandbox-1", "sha256:whatever")

	pod := &api.PodSandbox{Id: "sandbox-1"}
	if err := p.RemoveContainer(context.Background(), pod, &api.Container{Id: "ctr-1", PodSandboxId: "sandbox-1"}); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if _, ok := p.live.live["ctr-1"]; ok {
		t.Fatal("a removed container is still live")
	}

	p.live.admit("ctr-2", "sandbox-1", "sha256:whatever")
	if err := p.RemovePodSandbox(context.Background(), pod); err != nil {
		t.Fatalf("RemovePodSandbox: %v", err)
	}
	if len(p.live.live) != 0 {
		t.Fatalf("live = %v, want empty after the sandbox went away", p.live.live)
	}
}

// TestStartContainerRecordsTheAdmittingRule pins what makes an instance
// attributable: the rule that admitted it, not merely its digest.
func TestStartContainerRecordsTheAdmittingRule(t *testing.T) {
	doc := argvAllowlist("app", pushDigestA, nil)
	cfg := pullingConfig()
	cfg.Allowlist.AlwaysAllow = map[string]string{pushDigestB: "bootstrap"}
	p, _ := newCachedPlugin(cfg, doc)
	p.live = newLiveInstances()
	p.SetReady()

	pod := makePod("default", "pod")
	rule := makeCtrWithImage(pod.Id, "by-rule", "registry/repo@"+pushDigestA)
	floor := makeCtrWithImage(pod.Id, "by-floor", "registry/repo@"+pushDigestB)
	for _, ctr := range []*api.Container{rule, floor} {
		if err := p.StartContainer(context.Background(), pod, ctr); err != nil {
			t.Fatalf("StartContainer(%s): %v", ctr.Name, err)
		}
	}

	if got, want := p.live.live[rule.Id].ruleKey, ruleKeyOf(t, doc); got != want {
		t.Fatalf("rule key = %q, want %q", got, want)
	}
	if got := p.live.live[floor.Id].ruleKey; got != "" {
		t.Fatalf("always_allow instance tagged with rule %q, want none", got)
	}
}

// --- the barrier ---

// TestBarrierAdmitsUnderExactlyOneSnapshot runs creates against a policy that
// is being swapped underneath them. Both documents admit the digest under a
// different rule, so the rule an instance is recorded with says which snapshot
// decided it; the barrier makes that the snapshot the whole check saw.
func TestBarrierAdmitsUnderExactlyOneSnapshot(t *testing.T) {
	docs := map[uint64]*allowlist.Allowlist{
		1: argvAllowlist("blue", pushDigestA, nil),
		2: argvAllowlist("green", pushDigestA, nil),
	}
	keys := map[uint64]string{1: ruleKeyOf(t, docs[1]), 2: ruleKeyOf(t, docs[2])}

	store := newPolicyStore(nil)
	store.apply(docs[1], 1, policyDigest(t, docs[1]))
	p, _ := newCachedPlugin(pullingConfig(), docs[1])
	p.policy = store
	p.live = newLiveInstances()
	p.SetReady()

	// Resolve runs inside the check, so it is where the snapshot in force can
	// be observed mid-decision.
	var seen sync.Map // container ID -> version observed inside the check
	var current atomic.Pointer[api.Container]
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, imageRef string) (string, error) {
		if ctr := current.Load(); ctr != nil {
			seen.Store(ctr.GetId(), store.current().version)
		}
		return pushDigestA, nil
	}}

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for version := uint64(3); ; version++ {
			select {
			case <-stop:
				return
			default:
			}
			doc := docs[2-version%2]
			snap, release := store.halt()
			store.applyHalted(doc, version, snap.digest)
			release()
		}
	}()

	pod := makePod("default", "pod")
	for i := range 200 {
		ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo:tag")
		ctr.Id = "ctr-" + strconv.Itoa(i)
		current.Store(ctr)
		if err := p.StartContainer(context.Background(), pod, ctr); err != nil {
			t.Fatalf("StartContainer: %v", err)
		}
		version, ok := seen.Load(ctr.Id)
		if !ok {
			t.Fatalf("container %s never reached the resolver", ctr.Id)
		}
		want := keys[2-version.(uint64)%2]
		if got := p.live.live[ctr.Id].ruleKey; got != want {
			t.Fatalf("container admitted under snapshot %d recorded rule %s, want %s", version, got, want)
		}
	}
	close(stop)
	swapper.Wait()
}

// --- Synchronize and the pending set ---

func TestSynchronizeLeavesPendingInstancesAlone(t *testing.T) {
	source := argvAllowlist("app", pushDigestA, nil)
	target := argvAllowlist("app", pushDigestB, nil)

	tests := []struct {
		name     string
		pending  bool
		wantKill bool
	}{
		{name: "pending instance survives", pending: true},
		{name: "plain violation is stopped", wantKill: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := pullingConfig()
			cfg.Policy.EnforceExisting = true
			p, store := newCachedPlugin(cfg, source)
			p.live = newLiveInstances()
			p.SetReady()

			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo@"+pushDigestA)
			p.live.admit(ctr.Id, pod.Id, ruleKeyOf(t, source))
			if tt.pending {
				p.live.markPending(map[string]struct{}{ruleKeyOf(t, source): {}})
			}
			// The update switched: the node now enforces a policy that no
			// longer admits this instance's image.
			store.apply(target, 2, policyDigest(t, target))

			var killed []string
			p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
				killed = append(killed, id)
				return nil
			}}

			if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatalf("Synchronize: %v", err)
			}
			if got := len(killed) > 0; got != tt.wantKill {
				t.Fatalf("stopped = %v, want %v (killed %v)", got, tt.wantKill, killed)
			}
		})
	}
}

// TestNarrowedArgvMarksTheInstancePending drives the whole path: the digest
// stays allowed, only the command narrows, and the instance running the old
// command must still be pending.
func TestNarrowedArgvMarksTheInstancePending(t *testing.T) {
	source := argvAllowlist("app", pushDigestA, nil)
	target := argvAllowlist("app", pushDigestA, []string{"/bin/app", "--safe"})

	f := newSyncerFixture(t)
	f.cds.seed(source)
	f.sync(t)
	f.enroll(t)

	p, _ := newCachedPlugin(pullingConfig(), source)
	p.policy = f.store
	p.live = f.live
	p.SetReady()

	pod := makePod("default", "pod")
	ctr := makeCtrWithImageArgs(pod.Id, "ctr", "registry/repo@"+pushDigestA, []string{"/bin/app", "--wide"})
	if err := p.StartContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}

	f.cds.publish(target)
	f.sync(t)

	if !f.live.isPending(ctr.Id) {
		t.Fatal("an instance running the widest command is not pending after the command narrowed")
	}
	_, acks, _ := f.cds.recorded()
	if len(acks) != 1 || acks[0].Retired != 1 {
		t.Fatalf("acks = %+v, want one ack over one retired instance", acks)
	}

	// After the switch the same container must not be stopped, while a fresh
	// create of the old command is refused.
	f.cds.switchUpdate()
	f.sync(t)

	var killed []string
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		return nil
	}}
	p.cfg.Policy.EnforceExisting = true
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
	if len(killed) != 0 {
		t.Fatalf("stopped %v, want the pending instance left alone", killed)
	}

	fresh := makeCtrWithImageArgs(pod.Id, "fresh", "registry/repo@"+pushDigestA, []string{"/bin/app", "--wide"})
	if err := p.StartContainer(context.Background(), pod, fresh); err == nil {
		t.Fatal("a fresh create under the removed command was admitted")
	}
}
