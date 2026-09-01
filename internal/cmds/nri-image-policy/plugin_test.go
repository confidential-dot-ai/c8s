package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/mountidentity"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func newTestPlugin(cfg *config) *plugin {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	return &plugin{
		cfg:        cfg,
		audit:      audit.NewLogger(),
		logger:     slog.Default(),
		containerd: &fakeContainerd{},
	}
}

// fakeContainerd is the containerdOps a test drives. An unset hook panics, so a
// test that reaches containerd without arranging for it names the call it made.
type fakeContainerd struct {
	resolve func(ctx context.Context, imageRef string) (string, error)
	stop    func(ctx context.Context, containerID string) error
}

func (f *fakeContainerd) Resolve(ctx context.Context, imageRef string) (string, error) {
	if f.resolve == nil {
		panic("unexpected containerd resolve")
	}
	return f.resolve(ctx, imageRef)
}

func (f *fakeContainerd) StopContainer(ctx context.Context, containerID string) error {
	if f.stop == nil {
		panic("unexpected container kill")
	}
	return f.stop(ctx, containerID)
}

func TestCheckImage_MissingAnnotation_DenyEnabled(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
		},
	})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", "", nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != "container has no image annotation" {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckImage_MissingAnnotation_DenyDisabled(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: false,
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", "", nil)
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip, got %d", verdict)
	}
}

func TestCheckContainer_MissingAnnotation_SystemNamespaceDenied(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			DenyMissingAnnotation: true,
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	pod := makePod("kube-system", "pod")
	verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, makeCtr(pod.Id, "ctr"), "")
	if verdict != verdictDeny {
		t.Fatalf("a system namespace buys nothing without an image annotation, got %d", verdict)
	}
}

// --- Startup security gap tests ---

func makePod(namespace, name string) *api.PodSandbox {
	return &api.PodSandbox{
		Id:        name + "-id",
		Name:      name,
		Namespace: namespace,
	}
}

func makeCtr(podSandboxID, name string) *api.Container {
	return &api.Container{
		Id:           name + "-id",
		PodSandboxId: podSandboxID,
		Name:         name,
	}
}

// The pod-sandbox lifecycle feeds the inventory's sandbox set: Synchronize seeds
// it even while the container check is deferred, RunPodSandbox adds,
// RemovePodSandbox evicts.
func TestPodSandboxEventsFeedInventory(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{EnforceExisting: true}})
	p.inventory = newAdmissionInventory(t.TempDir())

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, known, _ := p.inventory.DigestsForSandbox("pod1-id"); !known {
		t.Fatal("Synchronize did not seed the inventory sandbox set while deferring")
	}

	if err := p.RunPodSandbox(context.Background(), makePod("default", "pod2")); err != nil {
		t.Fatal(err)
	}
	if _, _, known, _ := p.inventory.DigestsForSandbox("pod2-id"); !known {
		t.Fatal("RunPodSandbox did not record the sandbox")
	}

	if err := p.RemovePodSandbox(context.Background(), makePod("default", "pod2")); err != nil {
		t.Fatal(err)
	}
	if _, _, known, _ := p.inventory.DigestsForSandbox("pod2-id"); known {
		t.Fatal("RemovePodSandbox did not evict the sandbox")
	}
}

// Pod-sandbox events are subscribed exactly when the inventory is enabled.
func TestConfigureSubscribesPodSandboxEventsWithInventory(t *testing.T) {
	p := newTestPlugin(&config{})
	mask, err := p.Configure(context.Background(), "", "containerd", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	if mask.IsSet(api.Event_RUN_POD_SANDBOX) || mask.IsSet(api.Event_REMOVE_POD_SANDBOX) {
		t.Fatal("pod-sandbox events subscribed without an inventory")
	}

	p.inventory = newAdmissionInventory(t.TempDir())
	mask, err = p.Configure(context.Background(), "", "containerd", "2.0")
	if err != nil {
		t.Fatal(err)
	}
	if !mask.IsSet(api.Event_RUN_POD_SANDBOX) || !mask.IsSet(api.Event_REMOVE_POD_SANDBOX) {
		t.Fatal("pod-sandbox events not subscribed with the inventory enabled")
	}
}

func TestCreateContainer_NotReady_DeniesNonFloorImage(t *testing.T) {
	p := floorPlugin(t)
	// plugin is NOT ready (default zero value of atomic.Bool is false)

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error when plugin not ready and the image is not in the floor")
	}
	if !strings.HasPrefix(err.Error(), "image policy plugin initializing: ") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_NotReady_AdmitsFloorDigest(t *testing.T) {
	p := floorPlugin(t)

	// The digest rides the reference, so admission needs no containerd call
	// (fakeContainerd panics if one happens).
	pod := makePod("kube-system", "coredns")
	ctr := makeCtrWithImage(pod.Id, "coredns", "registry/repo@"+pushDigestA)

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("a floor digest should be admitted while initializing, got: %v", err)
	}
}

func TestCreateContainer_NotReady_AuditModeAllows(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "audit",
		},
	})

	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected audit mode to allow during init, got error: %v", err)
	}
}

func TestSynchronize_NotReady_Defers(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}

	updates, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}

	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredPods) != 1 {
		t.Fatalf("expected 1 deferred pod, got %d", len(p.deferredPods))
	}
	if len(p.deferredCtrs) != 1 {
		t.Fatalf("expected 1 deferred container, got %d", len(p.deferredCtrs))
	}
}

func TestSynchronize_NotReady_EnforceExistingDisabled_NoDeferral(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: false,
		},
	})

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}

	_, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredPods) != 0 {
		t.Fatalf("expected no deferred pods, got %d", len(p.deferredPods))
	}
}

func TestRunDeferredCheck_NothingDeferred(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})
	p.SetReady()

	// Should be a no-op without panic
	p.RunDeferredCheck(context.Background())
}

func TestCreateContainer_Ready_PassesThrough(t *testing.T) {
	p := &plugin{
		cfg: &config{
			Allowlist: allowlistConfig{Pull: pullConfig{URL: "http://wl.local:8080", Timeout: 30}},
			Policy: policyConfig{
				Mode:                  "fail-closed",
				DenyMissingAnnotation: true,
			},
		},
		audit:      audit.NewLogger(),
		logger:     slog.Default(),
		policy:     newPolicyStore(floorAllowlist(map[string]string{})),
		containerd: &fakeContainerd{},
	}
	p.SetReady()

	// Container with no image annotation and deny_missing_annotation=true
	// should go through the normal path and be denied (not the init guard).
	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from normal allowlist check path")
	}
	// Should be the "no image annotation" denial, not the "initializing" denial
	if err.Error() == "image policy plugin initializing, container creation denied" {
		t.Fatal("got init guard denial but plugin is ready — should use normal path")
	}
	expected := "container has no image annotation"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

// --- Label selector evaluation tests ---

func makePodWithLabels(namespace, name string, labels map[string]string) *api.PodSandbox {
	return &api.PodSandbox{
		Id:        name + "-id",
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

func mustCompileRule(t *testing.T, rule labelRule) labelRule {
	t.Helper()
	rules := []labelRule{rule}
	if err := validateLabelRules(rules); err != nil {
		t.Fatalf("compile label rule: %v", err)
	}
	return rules[0]
}

// --- evaluateRule tests ---

func TestEvaluateRule_AllExpressionsMustMatch(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"acme"}},
			{Key: "team", Operator: "Exists"},
		},
	})
	// Both match
	if !evaluateRule(rule, map[string]string{"tenant": "acme", "team": "backend"}) {
		t.Fatal("expected rule to pass when all expressions match")
	}
	// Only first matches
	if evaluateRule(rule, map[string]string{"tenant": "acme"}) {
		t.Fatal("expected rule to fail when not all expressions match")
	}
}

func TestEvaluateRule_NilLabels(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "Exists"},
		},
	})
	if evaluateRule(rule, nil) {
		t.Fatal("expected rule to fail with nil labels")
	}
}

func TestEvaluateRule_DoesNotExist_NilLabels(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "privileged", Operator: "DoesNotExist"},
		},
	})
	if !evaluateRule(rule, nil) {
		t.Fatal("expected DoesNotExist to pass with nil labels")
	}
}

func TestEvaluateRule_UncompiledRuleFailsClosed(t *testing.T) {
	rule := labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "Exists"},
		},
	}
	if evaluateRule(rule, map[string]string{"tenant": "acme"}) {
		t.Fatal("uncompiled label rule should fail closed")
	}
}

// --- checkLabels tests ---

func TestCheckContainer_SystemNamespace_LabelDenialStands(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})

	pod := makePod("kube-system", "pod")
	verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, makeCtr(pod.Id, "ctr"), "")
	if verdict != verdictDeny {
		t.Fatalf("a label denial in a system namespace must stand, got %d", verdict)
	}
}

func TestCheckLabels_RuleViolation(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme", "beta"}},
				}},
			},
		},
	})

	// Pod with wrong tenant value
	verdict, reason := p.checkLabels(p.cfg, "default", "pod", "ctr",
		map[string]string{"tenant": "gamma"})
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != `label rule "allowed-tenants" denied workload` {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckLabels_AllRulesPass(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme", "beta"}},
				}},
				{Name: "no-privileged", MatchExpressions: []labelExpression{
					{Key: "privileged", Operator: "DoesNotExist"},
				}},
			},
		},
	})

	verdict, _ := p.checkLabels(p.cfg, "default", "pod", "ctr",
		map[string]string{"tenant": "acme"})
	if verdict != verdictAllow {
		t.Fatalf("expected verdictAllow, got %d", verdict)
	}
}

func TestCheckLabels_FirstViolationWins(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "first-rule", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
				{Name: "second-rule", MatchExpressions: []labelExpression{
					{Key: "team", Operator: "Exists"},
				}},
			},
		},
	})

	// Both rules violated — first should be reported
	verdict, reason := p.checkLabels(p.cfg, "default", "pod", "ctr", map[string]string{})
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != `label rule "first-rule" denied workload` {
		t.Fatalf("expected first rule to be reported, got: %s", reason)
	}
}

// --- CreateContainer with label rules ---

func TestCreateContainer_LabelRuleDeny_FailClosed(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "fail-closed",
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme"}},
				}},
			},
		},
	})
	p.SetReady()

	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "evil"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from label rule denial")
	}
	if err.Error() != `label rule "allowed-tenants" denied workload` {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_LabelRuleDeny_AuditMode(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "audit",
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme"}},
				}},
			},
		},
	})
	p.SetReady()

	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "evil"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected audit mode to allow, got error: %v", err)
	}
}

func TestCreateContainer_AllowlistDisabled_SkipsImageCheck(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:                  "fail-closed",
			DenyMissingAnnotation: true,
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})
	p.SetReady()

	// Pod has tenant label, no image annotation — should pass because
	// allowlist is disabled (no URL), image check is skipped.
	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "acme"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected no error with allowlist disabled, got: %v", err)
	}
}

// mustDigest parses a digest string or fails the test.
func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

// newCachedPlugin builds a plugin whose policy store admits wl (applied as a
// version-1 pull over an empty floor).
func newCachedPlugin(cfg *config, wl *allowlist.Allowlist) (*plugin, *policyStore) {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	store := newPolicyStore(floorAllowlist(map[string]string{}))
	store.apply(wl, 1)
	p := &plugin{
		cfg:        cfg,
		policy:     store,
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
	}
	return p, store
}

// --- checkImage: digest-bearing references (no resolver needed) ---

func TestCheckImage_DigestInAllowlist_Allows(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef, nil)
	if verdict != verdictAllow {
		t.Fatalf("expected verdictAllow, got %d (reason=%q)", verdict, reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason on allow, got %q", reason)
	}
}

func TestCheckImage_DigestNotInAllowlist_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef, nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason on deny")
	}
}

func TestCheckImage_NoPolicyLoaded_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, s := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	s.snap.Store(nil) // no admission snapshot loaded

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef, nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when no policy is loaded, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason when no allowlist is available")
	}
}

// --- workload argv policy: floor admits any argv, workload gates on argv ---

// workloadAllowlist builds an allowlist with one workload container pinning the
// given digest to an exact entrypoint. The floor holds floorDigest (digest-only).
func workloadAllowlist(t *testing.T, floorDigest, wlDigest string, entrypoint []string) *allowlist.Allowlist {
	t.Helper()
	return &allowlist.Allowlist{
		Schema:  allowlist.Schema,
		Digests: map[string]string{floorDigest: "floor-image"},
		Workloads: map[string]allowlist.Workload{
			"w": {Containers: []allowlist.Container{{
				Digest:  mustDigest(t, wlDigest),
				Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: entrypoint},
				Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			}}},
		},
	}
}

func TestCheckImage_FloorDigest_AdmitsAnyArgv(t *testing.T) {
	// A floor digest is admitted regardless of the effective argv.
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestA, []string{"/anything", "--wild"})
	if verdict != verdictAllow {
		t.Fatalf("floor digest should admit any argv, got %d (reason=%q)", verdict, reason)
	}
}

func TestCheckImage_WorkloadDigest_ArgvMatchAdmits(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
	if verdict != verdictAllow {
		t.Fatalf("matching argv should admit workload digest, got %d (reason=%q)", verdict, reason)
	}
}

func TestCheckImage_WorkloadDigest_ArgvMismatchDenies(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, _ := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestB, []string{"/bin/evil"})
	if verdict != verdictDeny {
		t.Fatalf("non-matching argv should deny workload digest, got %d", verdict)
	}
}

// The two denials need different fixes — allowlist the image, versus correct the
// entry's argv policy — so the reason has to tell them apart.
func TestCheckImage_DenialSeparatesUnlistedFromArgvMismatch(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	_, argvMismatch := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestB, []string{"/bin/evil"})
	if !strings.Contains(argvMismatch, "satisfies no workload entry's argv policy") {
		t.Fatalf("a listed digest denied on argv should say so, got %q", argvMismatch)
	}

	_, unlisted := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestC, []string{"/bin/app"})
	if !strings.Contains(unlisted, "image not in allowlist") {
		t.Fatalf("an unlisted digest should keep the floor denial, got %q", unlisted)
	}
}

func TestCreateContainer_WorkloadArgv_MatchAndMismatch(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "floor-image"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))
	p.SetReady()

	pod := makePod("default", "mypod")

	match := makeCtrWithImageArgs(pod.Id, "match", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
	if _, _, err := p.CreateContainer(context.Background(), pod, match); err != nil {
		t.Fatalf("matching argv should be admitted, got: %v", err)
	}

	mismatch := makeCtrWithImageArgs(pod.Id, "mismatch", "registry/repo@"+pushDigestB, []string{"/bin/evil"})
	if _, _, err := p.CreateContainer(context.Background(), pod, mismatch); err == nil {
		t.Fatal("non-matching argv should be denied")
	}
}

// --- CreateContainer end-to-end through the image allowlist path ---

func makeCtrWithImage(podSandboxID, name, image string) *api.Container {
	return &api.Container{
		Id:           name + "-id",
		PodSandboxId: podSandboxID,
		Name:         name,
		Annotations:  map[string]string{annotationImageName: image},
	}
}

// makeCtrWithImageArgs is makeCtrWithImage plus the container's effective argv
// (NRI folds the OCI process.args into api.Container.Args).
func makeCtrWithImageArgs(podSandboxID, name, image string, args []string) *api.Container {
	ctr := makeCtrWithImage(podSandboxID, name, image)
	ctr.Args = args
	return ctr
}

func TestCreateContainer_DigestNotInAllowlist_FailClosed(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected denial for image not in allowlist")
	}
}

func TestCreateContainer_DigestNotInAllowlist_AuditAllows(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("audit mode should allow despite deny verdict, got: %v", err)
	}
}

func TestCreateContainer_DigestInAllowlist_Allows(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestA)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected allow for allowlisted digest, got: %v", err)
	}
}

// The pod annotation names the sandbox image, not this container's, so a
// container without its own annotation has no reference to check.
func TestCreateContainer_PodAnnotationDoesNotSupplyImage(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, DenyMissingAnnotation: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	pod.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestA}
	ctr := makeCtr(pod.Id, "myctr") // no annotations

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected denial: the container carries no image annotation")
	}
}

// --- checkExisting via deferred check (audit mode → no container kill attempted) ---

// assertDeferredCleared checks that RunDeferredCheck consumed the deferred state.
func assertDeferredCleared(t *testing.T, p *plugin) {
	t.Helper()
	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if p.deferredPods != nil || p.deferredCtrs != nil {
		t.Fatal("deferred state not cleared after RunDeferredCheck")
	}
}

func TestRunDeferredCheck_AuditMode_NoKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:            ModeAudit, // audit → never calls resolver.StopContainer
			EnforceExisting: true,
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "pod1")
	// Container image is NOT in the allowlist → would be denied, but audit
	// mode means checkExisting continues without attempting a kill.
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// Should run the check without reaching containerd (fakeContainerd panics).
	p.RunDeferredCheck(context.Background())
	assertDeferredCleared(t, p)
}

func TestRunDeferredCheck_OrphanContainer_Skipped(t *testing.T) {
	// A container whose pod sandbox is absent is skipped (podByID miss).
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	ctr := makeCtrWithImage("missing-pod-id", "orphan", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = nil
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	p.RunDeferredCheck(context.Background())
	assertDeferredCleared(t, p)
}

func TestRunDeferredCheck_EnforceExistingDisabled_NoOp(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// EnforceExisting=false → early return before clearing deferred state.
	p.RunDeferredCheck(context.Background())
	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredCtrs) != 1 || len(p.deferredPods) != 1 {
		t.Fatal("disabled check must leave deferred state untouched")
	}
}

// --- enforce_existing=false still rebuilds broker state across a restart ---

func TestSynchronize_EnforceExistingDisabled_BrokerRecordsWithoutKilling(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	allowed := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)
	denied := makeCtrWithImage(pod.Id, "ctr2", "registry/repo@"+pushDigestB)

	// Fail-closed, but enforce_existing off: the denied container must not reach
	// StopContainer (fakeContainerd panics).
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{allowed, denied}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec, ok := p.inventory.containers[allowed.Id]
	if !ok {
		t.Fatalf("allowlisted container not recorded in the inventory: %v", p.inventory.containers)
	}
	if rec.digest != pushDigestA {
		t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestA)
	}
	// The denial did not stop it, so /digests must report it: a sandbox whose
	// answer omits a running container reads as a workload it is not.
	if _, ok := p.inventory.containers[denied.Id]; !ok {
		t.Fatalf("a denied container left running is invisible to the inventory: %v", p.inventory.containers)
	}
	digests, _, _, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil {
		t.Fatalf("DigestsForSandbox: %v", err)
	}
	if !slices.Contains(digests, pushDigestB) {
		t.Fatalf("/digests omits the denied container: %v", digests)
	}
}

// The restart sequence in full: NRI replays Synchronize before the initial CDS
// pull completes, so recovery runs through the deferred path.
func TestSynchronize_EnforceExistingDisabled_NotReady_DefersThenRecords(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)

	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seeded, ok := p.inventory.containers[ctr.Id]
	if !ok {
		t.Fatal("synchronized container was absent from the pre-ready transition inventory")
	}
	if seeded.digest != pushDigestA {
		t.Fatalf("seeded digest = %q, want %q", seeded.digest, pushDigestA)
	}

	p.SetReady()
	p.RunDeferredCheck(context.Background())

	if _, ok := p.inventory.containers[ctr.Id]; !ok {
		t.Fatalf("deferred check did not record the container: %v", p.inventory.containers)
	}
}

func TestSynchronize_Ready_AuditMode_ChecksWithoutEnforcing(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	allowed := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)
	denied := makeCtrWithImage(pod.Id, "ctr2", "registry/repo@"+pushDigestB)

	// Audit mode must run the check without enforcement: a denied container
	// reaching StopContainer would panic (fakeContainerd).
	updates, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{allowed, denied})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}
	if _, ok := p.inventory.containers[allowed.Id]; !ok {
		t.Fatalf("check did not record the allowed container in the inventory: %v", p.inventory.containers)
	}
	// Audit mode leaves the denied container running, so it belongs in /digests.
	if _, ok := p.inventory.containers[denied.Id]; !ok {
		t.Fatalf("audit mode left a container running and unrecorded: %v", p.inventory.containers)
	}
}

// --- System-component admission: digest-keyed, recorded everywhere ---

// captureAudit collects the audit events fn emits on the default slog logger.
// Swaps a process-global: not safe under t.Parallel.
func captureAudit(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	fn()

	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if rec["msg"] == "audit" {
			events = append(events, rec)
		}
	}
	return events
}

// floorPlugin admits pushDigestA via the always_allow floor, and carries an
// inventory. The store is floor-seeded (no pull applied), the state a plugin
// is in before its first CDS fetch.
func floorPlugin(t *testing.T) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
		},
	}
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(floorAllowlist(cfg.Allowlist.AlwaysAllow)),
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
	}
	p.inventory = newAdmissionInventory("/proc")
	return p
}

// Admission keys on the image digest alone: a non-floor image is denied in
// every namespace, kube-system included.
func TestCheckContainer_SystemNamespace_NonFloorImage_Denied(t *testing.T) {
	p := floorPlugin(t)
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestB // not in the floor
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictDeny {
		t.Fatalf("a non-floor image in kube-system must be denied, got verdict %d", verdict)
	}
	if len(events) != 1 || events[0]["action"] != "deny" || events[0]["reason"] != "not_in_allowlist" {
		t.Fatalf("want exactly the digest denial, got %v", events)
	}
}

func TestFloorContainerIsRecordedOnEveryPath(t *testing.T) {
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestA // in the floor
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	paths := []struct {
		name string
		run  func(*testing.T, *plugin)
	}{
		{"create hook", func(t *testing.T, p *plugin) {
			p.SetReady()
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("floor digest should be admitted: %v", err)
			}
		}},
		{"create hook while initializing", func(t *testing.T, p *plugin) {
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("floor digest should be admitted: %v", err)
			}
		}},
		{"startup check", func(t *testing.T, p *plugin) {
			p.SetReady()
			if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatal(err)
			}
		}},
		{"deferred check", func(t *testing.T, p *plugin) {
			if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatal(err)
			}
			p.SetReady()
			p.RunDeferredCheck(context.Background())
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			p := floorPlugin(t)
			path.run(t, p)

			rec, ok := p.inventory.containers[ctr.Id]
			if !ok {
				t.Fatalf("floor container is invisible to the inventory: %v", p.inventory.containers)
			}
			if rec.digest != pushDigestA {
				t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestA)
			}
			digests, _, known, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || !known {
				t.Fatalf("DigestsForSandbox(%s) = known %v, err %v", pod.Id, known, err)
			}
			if !slices.Contains(digests, pushDigestA) {
				t.Fatalf("/digests omits the floor container: %v", digests)
			}
		})
	}
}

// A platform component takes the ordinary allow: one verified event, nothing
// else.
func TestCheckContainer_SystemNamespace_FloorImageIsPlainAllow(t *testing.T) {
	p := floorPlugin(t)
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestA // in the floor
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictAllow {
		t.Fatalf("a floor image should be a plain allow, got verdict %d", verdict)
	}
	if len(events) != 1 || events[0]["reason"] != "verified" {
		t.Fatalf("want exactly the verified allow, got %v", events)
	}
}

// No namespace rescues a non-floor image — exact or near-miss.
func TestCheckContainer_NamespaceNeverRescues(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB // not in the floor
	for _, namespace := range []string{
		"kube-system",
		"local-path-storage",
		"",
		"kube-system ",
		" kube-system",
		"KUBE-SYSTEM",
		"Kube-System",
		"kube-system.",
		"kube-system\x00",
		"kube-system\n",
		"kube-systems",
		"kube_system",
	} {
		t.Run(fmt.Sprintf("%q", namespace), func(t *testing.T) {
			p := floorPlugin(t)
			pod := makePod(namespace, "pod1")
			ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

			verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
			if verdict != verdictDeny {
				t.Fatalf("namespace %q: verdict %d, want verdictDeny", namespace, verdict)
			}
		})
	}
}

// Pre-Ready the admission decision resolves a tag against the floor, but the
// inventory record keeps the inline-only contract: no digest is committed
// without one riding the reference, and the sandbox answer stays closed.
func TestCreateContainer_NotReady_ResolvesForAdmission_RecordsInlineOnly(t *testing.T) {
	p := floorPlugin(t) // not ready
	var resolved []string
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
		resolved = append(resolved, ref)
		return pushDigestA, nil
	}}

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest") // no inline digest

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("a tag resolving to the floor should be admitted: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("admission did not resolve the tag: %v", resolved)
	}
	rec, ok := p.inventory.containers[ctr.Id]
	if !ok {
		t.Fatalf("bootstrap container not recorded: %v", p.inventory.containers)
	}
	if rec.digest != "" {
		t.Fatalf("the bootstrap path resolved a digest, got %q", rec.digest)
	}
	if _, _, _, err := p.inventory.DigestsForSandbox(pod.Id); err == nil {
		t.Fatal("an unresolved digest must fail the sandbox answer closed")
	}
}

// The denial twin: a tag resolving outside the floor is refused while
// initializing, in any namespace.
func TestCreateContainer_NotReady_TagOutsideFloor_Denied(t *testing.T) {
	p := floorPlugin(t) // not ready
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
		return pushDigestB, nil
	}}

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest")

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("a tag resolving outside the floor must be denied while initializing")
	}
}

// A tag that fails to resolve during init is denied, not admitted: the
// bootstrap window enforces the floor even when containerd cannot answer
// inside NRI's timeout.
func TestCreateContainer_NotReady_ResolveFails_Denied(t *testing.T) {
	p := floorPlugin(t) // not ready
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, _ string) (string, error) {
		return "", errors.New("resolve timed out")
	}}

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest")

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("a tag that fails to resolve while initializing must be denied")
	}
}

// Audit mode admits what it denies, so what it admits it must record.
func TestCreateContainer_AuditModeDenial_IsRecorded(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("audit mode should admit: %v", err)
	}
	rec, ok := p.inventory.containers[ctr.Id]
	if !ok {
		t.Fatalf("audit mode admitted a container it did not record: %v", p.inventory.containers)
	}
	if rec.digest != pushDigestB {
		t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestB)
	}
}

func TestCheckExisting_RecordsBeforeAttemptingTheKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	var killed []string
	var recordedAtKill bool
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		_, recordedAtKill = p.inventory.containers[denied.Id]
		return errors.New("kill not delivered")
	}}

	p.checkExisting(context.Background(), p.cfg, []*api.PodSandbox{pod}, []*api.Container{denied})

	if len(killed) != 1 || killed[0] != denied.Id {
		t.Fatalf("the kill was not attempted: %v", killed)
	}
	if !recordedAtKill {
		t.Fatal("the container was recorded only after the kill was attempted")
	}
	if _, ok := p.inventory.containers[denied.Id]; !ok {
		t.Fatal("an undeliverable kill left the container unrecorded")
	}
}

// enforce_existing stops a foreign container in kube-system: the kill path
// never reads the namespace, so an exempt name does not spare a non-floor
// image (issue #96's enforce case).
func TestCheckExisting_KubeSystemForeignContainerIsStopped(t *testing.T) {
	p := floorPlugin(t)
	p.SetReady()

	pod := makePod("kube-system", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB) // not in the floor

	var killed []string
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		return nil
	}}

	p.checkExisting(context.Background(), p.cfg, []*api.PodSandbox{pod}, []*api.Container{denied})

	if len(killed) != 1 || killed[0] != denied.Id {
		t.Fatalf("a non-floor container in kube-system must be stopped, got %v", killed)
	}
}

// A container whose sandbox is absent from the Synchronize list runs like any
// other, so the sandbox's answer must carry it.
func TestCheckExisting_OrphanContainerIsStillRecorded(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	orphan := makeCtrWithImage("missing-pod-id", "orphan", "registry/repo@"+pushDigestB)
	if _, err := p.Synchronize(context.Background(), nil, []*api.Container{orphan}); err != nil {
		t.Fatal(err)
	}

	if _, ok := p.inventory.containers[orphan.Id]; !ok {
		t.Fatalf("a container with no pod in the list went unrecorded: %v", p.inventory.containers)
	}
	digests, _, known, err := p.inventory.DigestsForSandbox("missing-pod-id")
	if err != nil || !known {
		t.Fatalf("DigestsForSandbox = known %v, err %v", known, err)
	}
	if !slices.Contains(digests, pushDigestB) {
		t.Fatalf("the sandbox answer launders the orphan: %v", digests)
	}
}

// Only the pre-allowlist hook skips containerd; the startup path resolves.
func TestCheckExisting_ResolvesTagOnlyReference(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	var resolved []string
	p.containerd = &fakeContainerd{resolve: func(_ context.Context, ref string) (string, error) {
		resolved = append(resolved, ref)
		return pushDigestA, nil
	}}
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest")
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatal(err)
	}

	if len(resolved) == 0 {
		t.Fatal("the startup path recorded a tag-only reference without resolving it")
	}
	if rec := p.inventory.containers[ctr.Id]; rec.digest != pushDigestA {
		t.Fatalf("recorded digest = %q, want the resolved %q", rec.digest, pushDigestA)
	}
}

// argv reaches MatchWorkload, so the recorded value must be the container's.
func TestCreateContainer_RecordsTheContainerArgv(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	argv := []string{"/bin/app", "--serve"}
	ctr := makeCtrWithImageArgs(pod.Id, "ctr1", "registry/repo@"+pushDigestA, argv)

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("allowlisted digest should be admitted: %v", err)
	}
	if rec := p.inventory.containers[ctr.Id]; !slices.Equal(rec.argv, argv) {
		t.Fatalf("recorded argv = %v, want %v", rec.argv, argv)
	}
	_, containers, _, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil {
		t.Fatalf("DigestsForSandbox: %v", err)
	}
	if len(containers) != 1 || !slices.Equal(containers[0].Argv, argv) {
		t.Fatalf("the sandbox answer reports argv %v, want %v", containers, argv)
	}
}

// A container the create hook rejected never ran.
func TestCreateContainer_DeniedContainerIsNotRecorded(t *testing.T) {
	p := floorPlugin(t)
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("expected denial for an image not in the floor")
	}
	if _, ok := p.inventory.containers[ctr.Id]; ok {
		t.Fatal("a denied container must not be recorded in the inventory")
	}
}

// --- Configure ---

func TestConfigure_SetsCreateContainerMask(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	mask, err := p.Configure(context.Background(), "", "containerd", "1.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want api.EventMask
	want.Set(api.Event_CREATE_CONTAINER)
	if mask != want {
		t.Fatalf("mask = %v, want %v", mask, want)
	}
}

// The node-CVM path must not turn missing runtime evidence into an observed
// empty set. Exact policy fails closed if a caller bypasses checkContainer and
// does not supply the NRI observation.
func TestCheckImage_ExactMountAndEnvPolicyRequiresObservation(t *testing.T) {
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	c := al.Workloads["w"].Containers[0]
	c.Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact}
	c.Env = allowlist.EnvPolicy{Policy: allowlist.PolicyExact}
	al.Workloads["w"].Containers[0] = c

	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, al)

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
	if verdict != verdictDeny {
		t.Fatalf("unobserved exact policy got verdict %d (reason=%q), want deny", verdict, reason)
	}

	// Non-vacuity: an observed disallowed mount is also refused.
	if p.policy.current().index.AdmitsContainer(allowlist.RunningContainer{
		Digest:         pushDigestB,
		Argv:           []string{"/bin/app", "--serve"},
		BindMounts:     []string{"/injected"},
		MountsObserved: true,
		EnvObserved:    true,
	}) {
		t.Error("the entry admitted a reported bind mount; the exact-empty policy is not live")
	}
}

func TestObserveCRIContainerReportsBindDestinationsAndEnvNames(t *testing.T) {
	ctr := &api.Container{
		Mounts: []*api.Mount{
			{Type: "bind", Source: "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/a", Destination: "/app/a"},
			{Source: "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~configmap/b", Destination: "/app/b"},
			{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
			{Type: "bind", Source: "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/a", Destination: "/app/a"},
		},
		Env: []string{"PATH=/bin", "TOKEN=secret", "PATH=/usr/bin", "EMPTY=", "HOST_IP=10.0.0.7", "HOST_IP=10.0.0.8"},
	}
	got := observeCRIContainer(&api.PodSandbox{Uid: "p1"}, ctr)
	if !slices.Equal(got.bindMounts, []string{"/app/a", "/app/b"}) {
		t.Fatalf("bind mounts = %v", got.bindMounts)
	}
	if got.bindMountKinds["/app/a"] != "unknown" || got.bindMountKinds["/app/b"] != "node" {
		t.Fatalf("bind mount kinds = %v", got.bindMountKinds)
	}
	if !slices.Equal(got.envNames, []string{"EMPTY", "HOST_IP", "PATH", "TOKEN"}) {
		t.Fatalf("env names = %v", got.envNames)
	}
	for _, item := range got.envNames {
		if strings.Contains(item, "secret") {
			t.Fatal("environment value entered the observation")
		}
	}
	if _, ok := got.envValues["HOST_IP"]; ok {
		t.Fatal("duplicate HOST_IP produced an argv-binding value")
	}
}

func TestMountSourceClassificationRejectsPathAndPodSpoofing(t *testing.T) {
	tmpfs := func(string) (mountidentity.Evidence, error) {
		return mountidentity.Evidence{Filesystem: int64(unix.TMPFS_MAGIC), Mountpoint: true, Canonical: true}, nil
	}
	disk := func(string) (mountidentity.Evidence, error) {
		return mountidentity.Evidence{Mountpoint: true, Canonical: true}, nil
	}
	current := "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/public-tls"
	if got := classifyMountSourceWithEvidence("p1", "app", current, tmpfs); got != "private" {
		t.Fatalf("current Pod tmpfs = %q, want private", got)
	}
	if got := classifyMountSourceWithEvidence("p1", "app", current, disk); got != "node" {
		t.Fatalf("current Pod disk emptyDir = %q, want node", got)
	}
	notMountpoint := func(string) (mountidentity.Evidence, error) {
		return mountidentity.Evidence{Filesystem: int64(unix.TMPFS_MAGIC), Canonical: true}, nil
	}
	if got := classifyMountSourceWithEvidence("p1", "app", current, notMountpoint); got != "node" {
		t.Fatalf("tmpfs directory without mount identity = %q, want node", got)
	}
	for name, source := range map[string]string{
		"victim UID":          "/var/lib/kubelet/pods/victim/volumes/kubernetes.io~empty-dir/public-tls",
		"UID prefix":          "/var/lib/kubelet/pods/p1-evil/volumes/kubernetes.io~empty-dir/public-tls",
		"embedded substring":  "/host/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/public-tls",
		"hostPath plugin":     "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~host-path/public-tls",
		"wrong subPath owner": "/var/lib/kubelet/pods/p1/volume-subpaths/public-tls/other/0",
	} {
		t.Run(name, func(t *testing.T) {
			if got := classifyMountSourceWithEvidence("p1", "app", source, tmpfs); got != "node" {
				t.Fatalf("spoof source %q classified %q, want node", source, got)
			}
		})
	}
}

func TestPolicyActivationIsAtomicWithContainerAdmissionAndRecord(t *testing.T) {
	store := newPolicyStore(floorAllowlist(map[string]string{pushDigestA: "cold floor"}))
	inventory := newAdmissionInventory(t.TempDir(), store)
	entered := make(chan struct{})
	release := make(chan struct{})
	store.setTransitionGuard(func(policy *allowlist.Allowlist, index *allowlist.Index) error {
		close(entered)
		<-release
		return inventory.admitsLiveRuntime(policy, index)
	})
	p := newTestPlugin(&config{
		Policy:    policyConfig{Mode: ModeFailClosed},
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "cold floor"}},
	})
	p.policy = store
	p.inventory = inventory
	p.SetReady()

	active := floorAllowlist(map[string]string{pushDigestB: "active"})
	applyDone := make(chan error, 1)
	go func() {
		applied, err := store.applyChecked(active, 1)
		if err == nil && !applied {
			err = errors.New("policy was not applied")
		}
		applyDone <- err
	}()
	<-entered

	pod := &api.PodSandbox{Id: "sandbox", Name: "pod", Namespace: "default", Uid: "p1"}
	ctr := makeCtrWithImage(pod.Id, "old-floor", "repo@"+pushDigestA)
	createDone := make(chan error, 1)
	go func() {
		_, _, err := p.CreateContainer(context.Background(), pod, ctr)
		createDone <- err
	}()
	select {
	case err := <-createDone:
		t.Fatalf("container admission crossed an in-progress transition: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-createDone; err == nil {
		t.Fatal("old-floor container entered after active policy transition")
	}
	if _, ok := inventory.containers[ctr.Id]; ok {
		t.Fatal("denied old-floor container was recorded as running")
	}
}

func TestPreReadySynchronizeSeedsPolicyTransitionGuard(t *testing.T) {
	store := newPolicyStore(floorAllowlist(map[string]string{pushDigestA: "cold floor"}))
	p := newTestPlugin(&config{
		Policy:    policyConfig{Mode: ModeFailClosed},
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "cold floor"}},
	})
	p.policy = store
	p.inventory = newAdmissionInventory(t.TempDir(), store)
	store.setTransitionGuard(p.inventory.admitsLiveRuntime)
	pod := &api.PodSandbox{Id: "sandbox", Name: "system", Namespace: "c8s-system", Uid: "p1"}
	ctr := makeCtrWithImage(pod.Id, "system", "repo@"+pushDigestA)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.inventory.containers[ctr.Id]; !ok {
		t.Fatal("pre-ready synchronization omitted a live container from the transition inventory")
	}
	if applied, err := store.applyChecked(floorAllowlist(map[string]string{pushDigestB: "active"}), 1); err == nil || applied {
		t.Fatalf("policy uncovered a synchronized live container: applied=%v err=%v", applied, err)
	}
}

func TestCheckContainerEnforcesObservedMountAndEnvPolicy(t *testing.T) {
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	c := al.Workloads["w"].Containers[0]
	c.Mounts = allowlist.MountPolicy{
		Policy:       allowlist.PolicyExact,
		Destinations: []string{"/config"},
		Kinds:        map[string]string{"/config": "node"},
	}
	c.Env = allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"PATH"}}
	al.Workloads["w"] = allowlist.Workload{Containers: []allowlist.Container{c}}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "bootstrap"}}}, al)
	pod := &api.PodSandbox{Namespace: "default", Name: "app", Uid: "p1"}
	base := &api.Container{
		Name: "app", Args: []string{"/bin/app", "--serve"},
		Mounts: []*api.Mount{{Type: "bind", Source: "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~configmap/config", Destination: "/config"}},
		Env:    []string{"PATH=/bin"},
	}

	if verdict, reason := p.checkContainer(context.Background(), p.cfg, pod, base, "repo@"+pushDigestB); verdict != verdictAllow {
		t.Fatalf("declared runtime fields: verdict=%d reason=%q", verdict, reason)
	}

	withInjectedEnv := proto.Clone(base).(*api.Container)
	withInjectedEnv.Env = []string{"PATH=/bin", "LD_PRELOAD=/host/code.so"}
	if verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, withInjectedEnv, "repo@"+pushDigestB); verdict != verdictDeny {
		t.Fatal("undeclared environment name was admitted")
	}

	withInjectedMount := proto.Clone(base).(*api.Container)
	withInjectedMount.Mounts = append(slices.Clone(base.Mounts), &api.Mount{Type: "bind", Source: "/host/code", Destination: "/bin/app"})
	if verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, withInjectedMount, "repo@"+pushDigestB); verdict != verdictDeny {
		t.Fatal("undeclared bind destination was admitted")
	}

}

func TestCheckContainerBindsFinalArgvToUniqueCRIEnvValue(t *testing.T) {
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app", "--url=http://$(HOST_IP):8400"})
	c := al.Workloads["w"].Containers[0]
	c.Command.EnvBindings = []allowlist.ArgvEnvBinding{{Index: 1, Names: []string{"HOST_IP"}}}
	c.Args = allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny}
	c.Env = allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"HOST_IP"}}
	al.Workloads["w"] = allowlist.Workload{Containers: []allowlist.Container{c}}
	p, _ := newCachedPlugin(&config{
		Policy:    policyConfig{Mode: ModeFailClosed},
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "bootstrap"}},
	}, al)
	pod := &api.PodSandbox{Namespace: "default", Name: "app", Uid: "p1"}
	base := &api.Container{Name: "app", Args: []string{"/bin/app", "--url=http://10.0.0.7:8400"}, Env: []string{"HOST_IP=10.0.0.7"}}
	if verdict, reason := p.checkContainer(context.Background(), p.cfg, pod, base, "repo@"+pushDigestB); verdict != verdictAllow {
		t.Fatalf("bound final argv: verdict=%d reason=%q", verdict, reason)
	}
	changed := proto.Clone(base).(*api.Container)
	changed.Env = []string{"HOST_IP=10.0.0.8"}
	if verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, changed, "repo@"+pushDigestB); verdict != verdictDeny {
		t.Fatal("changed downward-API value admitted the prior argv")
	}
	duplicate := proto.Clone(base).(*api.Container)
	duplicate.Env = []string{"HOST_IP=10.0.0.7", "HOST_IP=10.0.0.8"}
	if verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, duplicate, "repo@"+pushDigestB); verdict != verdictDeny {
		t.Fatal("duplicate downward-API values admitted a bound argv")
	}
}
