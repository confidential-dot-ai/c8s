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

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/containerd/nri/pkg/api"
)

func newTestPlugin(cfg *config) *plugin {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	p := &plugin{
		cfg:    cfg,
		audit:  audit.NewLogger(),
		logger: slog.Default(),
	}
	noContainerd(p)
	return p
}

// noContainerd makes any containerd call a named panic. Tests that need one
// rebind the field; the rest must stay on digest-bearing references.
func noContainerd(p *plugin) {
	p.resolve = func(context.Context, string) (string, error) { panic("unexpected containerd resolve") }
	p.stopContainer = func(context.Context, string) error { panic("unexpected container kill") }
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

func TestCheckImage_MissingAnnotation_ExemptNamespaceStillDenied(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", "", nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
}

func TestCheckContainer_MissingAnnotation_ExemptNamespaceAdmitted(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	pod := makePod("kube-system", "pod")
	verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, makeCtr(pod.Id, "ctr"), "")
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
	}
}

func TestCheckImage_NonExemptSystemNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-node-lease", "pod", "ctr", "", nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny for non-exempt namespace, got %d", verdict)
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

func TestCreateContainer_NotReady_DenyNonExempt(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:             "fail-closed",
			ExemptNamespaces: []string{"kube-system"},
		},
	})
	// plugin is NOT ready (default zero value of atomic.Bool is false)

	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error when plugin not ready and namespace non-exempt")
	}
	if err.Error() != "image policy plugin initializing, container creation denied" {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_NotReady_AllowExemptNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:             "fail-closed",
			ExemptNamespaces: []string{"kube-system"},
		},
	})

	pod := makePod("kube-system", "coredns")
	ctr := makeCtr(pod.Id, "coredns")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected exempt namespace to be allowed, got error: %v", err)
	}
}

func TestCreateContainer_NotReady_AuditModeAllows(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:             "audit",
			ExemptNamespaces: []string{"kube-system"},
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
				ExemptNamespaces:      []string{"kube-system"},
			},
		},
		audit:  audit.NewLogger(),
		logger: slog.Default(),
		policy: newPolicyStore(floorAllowlist(map[string]string{})),
	}
	noContainerd(p)
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

func TestCheckLabels_ExemptNamespaceStillEvaluatesRules(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			ExemptNamespaces: []string{"kube-system"},
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})

	verdict, _ := p.checkLabels(p.cfg, "kube-system", "pod", "ctr", nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
}

func TestCheckContainer_ExemptNamespace_OverridesLabelDenial(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			ExemptNamespaces: []string{"kube-system"},
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})

	pod := makePod("kube-system", "pod")
	verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, makeCtr(pod.Id, "ctr"), "")
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
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
		cfg:    cfg,
		policy: store,
		audit:  audit.NewLogger(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	noContainerd(p)
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

func TestCheckImage_ExemptNamespace_StillCheckedAgainstAllowlist(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB // not in allowlist
	p, _ := newCachedPlugin(&config{Policy: policyConfig{
		Mode:             ModeFailClosed,
		ExemptNamespaces: []string{"kube-system"},
	}}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", imageRef, nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
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

	// Should run the check without reaching containerd (noContainerd panics).
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
	// stopContainer (noContainerd panics).
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
	if len(p.inventory.containers) != 0 {
		t.Fatal("nothing should be recorded before the plugin is ready")
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
	// reaching stopContainer would panic (noContainerd).
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

// --- Namespace exemption: ordering and inventory ---

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

// exemptPlugin admits pushDigestA only, exempts kube-system, and carries an
// inventory.
func exemptPlugin(t *testing.T) *plugin {
	t.Helper()
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.inventory = newAdmissionInventory("/proc")
	return p
}

func TestCheckContainer_ExemptNamespace_DigestCheckedBeforeExemption(t *testing.T) {
	p := exemptPlugin(t)
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestB // not in the allowlist
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictSkip {
		t.Fatalf("exempt namespace should still be admitted, got verdict %d", verdict)
	}
	if len(events) != 2 {
		t.Fatalf("want the digest denial then the exemption, got %d events: %v", len(events), events)
	}
	if events[0]["action"] != "deny" || events[0]["reason"] != "not_in_allowlist" {
		t.Fatalf("the digest check must run first, got %v", events[0])
	}
	if events[1]["reason"] != "namespace_exempt" {
		t.Fatalf("the exemption must be applied after the digest check, got %v", events[1])
	}
}

func TestCheckContainer_ExemptNamespace_LabelDenialDoesNotSkipDigestCheck(t *testing.T) {
	p := exemptPlugin(t)
	p.cfg.Policy.LabelRules = []labelRule{mustCompileRule(t, labelRule{
		Name:             "require-tenant",
		MatchExpressions: []labelExpression{{Key: "tenant", Operator: "Exists"}},
	})}

	pod := makePodWithLabels("kube-system", "pod1", nil) // violates require-tenant
	imageRef := "registry/repo@" + pushDigestB
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictSkip {
		t.Fatalf("exempt namespace should still be admitted, got verdict %d", verdict)
	}
	var sawImageDenial bool
	for _, e := range events {
		if e["action"] == "deny" && e["reason"] == "not_in_allowlist" {
			sawImageDenial = true
		}
	}
	if !sawImageDenial {
		t.Fatalf("a label denial suppressed the digest check: %v", events)
	}
}

func TestExemptNamespaceContainerIsRecordedOnEveryPath(t *testing.T) {
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestB // not in the allowlist
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	paths := []struct {
		name string
		run  func(*testing.T, *plugin)
	}{
		{"create hook", func(t *testing.T, p *plugin) {
			p.SetReady()
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("exempt namespace should be admitted: %v", err)
			}
		}},
		{"create hook while initializing", func(t *testing.T, p *plugin) {
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("exempt namespace should be admitted: %v", err)
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
			p := exemptPlugin(t)
			path.run(t, p)

			rec, ok := p.inventory.containers[ctr.Id]
			if !ok {
				t.Fatalf("exempt container is invisible to the inventory: %v", p.inventory.containers)
			}
			if rec.digest != pushDigestB {
				t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestB)
			}
			digests, _, known, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || !known {
				t.Fatalf("DigestsForSandbox(%s) = known %v, err %v", pod.Id, known, err)
			}
			if !slices.Contains(digests, pushDigestB) {
				t.Fatalf("/digests omits the exempt container: %v", digests)
			}
		})
	}
}

// Platform components on a default install take the ordinary allow, not the
// exemption: the exemption leaves no trace when nothing denied.
func TestCheckContainer_ExemptNamespace_AllowlistedImageIsPlainAllow(t *testing.T) {
	p := exemptPlugin(t)
	pod := makePod("kube-system", "pod1")
	imageRef := "registry/repo@" + pushDigestA // in the allowlist
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictAllow {
		t.Fatalf("an allowlisted image should be a plain allow, got verdict %d", verdict)
	}
	var sawVerified bool
	for _, e := range events {
		if e["reason"] == "namespace_exempt" {
			t.Fatalf("the exemption fired with nothing to override: %v", events)
		}
		sawVerified = sawVerified || e["reason"] == "verified"
	}
	if !sawVerified {
		t.Fatalf("the digest check did not run: %v", events)
	}
}

// The overridden denial must stay visible: an exemption that admits a container
// a rule denied is the event an operator needs to see.
func TestCheckContainer_ExemptNamespace_LabelDenialIsAuditedAsOverridden(t *testing.T) {
	p := exemptPlugin(t)
	p.cfg.Policy.LabelRules = []labelRule{mustCompileRule(t, labelRule{
		Name:             "require-tenant",
		MatchExpressions: []labelExpression{{Key: "tenant", Operator: "Exists"}},
	})}

	pod := makePodWithLabels("kube-system", "pod1", nil) // violates require-tenant
	imageRef := "registry/repo@" + pushDigestA           // but the image is allowlisted
	ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

	var verdict imageVerdict
	events := captureAudit(t, func() {
		verdict, _ = p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
	})

	if verdict != verdictSkip {
		t.Fatalf("a label denial the exemption overrode should be verdictSkip, got %d", verdict)
	}
	var exemptEvent map[string]any
	for _, e := range events {
		if e["reason"] == "namespace_exempt" {
			exemptEvent = e
		}
	}
	if exemptEvent == nil {
		t.Fatalf("an allowlisted image erased the record of the overridden label rule: %v", events)
	}
	if got, _ := exemptEvent["overrides"].(string); !strings.Contains(got, "require-tenant") {
		t.Fatalf("the exemption event does not name the denial it overturned: %q", got)
	}
}

func TestCheckContainer_NamespaceNearMissesAreNotExempt(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB // not in the allowlist
	for _, tc := range []struct {
		namespace string
		want      imageVerdict
	}{
		{"kube-system", verdictSkip}, // positive control: the exemption does fire
		{"", verdictDeny},
		{"kube-system ", verdictDeny},
		{" kube-system", verdictDeny},
		{"KUBE-SYSTEM", verdictDeny},
		{"Kube-System", verdictDeny},
		{"kube-system.", verdictDeny},
		{"kube-system\x00", verdictDeny},
		{"kube-system\n", verdictDeny},
		{"kube-systems", verdictDeny},
		{"kube_system", verdictDeny},
	} {
		t.Run(fmt.Sprintf("%q", tc.namespace), func(t *testing.T) {
			p := exemptPlugin(t)
			pod := makePod(tc.namespace, "pod1")
			ctr := makeCtrWithImage(pod.Id, "ctr1", imageRef)

			verdict, _ := p.checkContainer(context.Background(), p.cfg, pod, ctr, imageRef)
			if verdict != tc.want {
				t.Fatalf("namespace %q: verdict %d, want %d", tc.namespace, verdict, tc.want)
			}
		})
	}
}

// noContainerd panics if this path reaches the image store.
func TestCreateContainer_NotReady_RecordsWithoutResolving(t *testing.T) {
	p := exemptPlugin(t) // not ready
	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo:latest") // no inline digest

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("exempt namespace should be admitted: %v", err)
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
	p.stopContainer = func(_ context.Context, id string) error {
		killed = append(killed, id)
		_, recordedAtKill = p.inventory.containers[denied.Id]
		return errors.New("kill not delivered")
	}

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
	p.resolve = func(_ context.Context, ref string) (string, error) {
		resolved = append(resolved, ref)
		return "registry/repo@" + pushDigestA, nil
	}
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
	p := exemptPlugin(t)
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("expected denial for an image not in the allowlist")
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
