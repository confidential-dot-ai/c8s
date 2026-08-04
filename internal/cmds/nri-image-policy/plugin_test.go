package nriimagepolicy

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/containerd/nri/pkg/api"
)

func newTestPlugin(cfg *config) *plugin {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	return &plugin{
		cfg:      cfg,
		resolver: &ctrdresolver.Resolver{},
		audit:    audit.NewLogger(),
		logger:   slog.Default(),
	}
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

func TestCheckImage_MissingAnnotation_ExemptNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", "", nil)
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
		resolver: &ctrdresolver.Resolver{},
		audit:    audit.NewLogger(),
		logger:   slog.Default(),
		policy:   newPolicyStore(floorAllowlist(map[string]string{})),
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

func TestCheckLabels_ExemptNamespace(t *testing.T) {
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
// version-1 pull over an empty floor). The resolver is a zero-value placeholder;
// tests must only exercise digest-bearing image references so resolver.Resolve
// is never reached (no real containerd socket).
func newCachedPlugin(cfg *config, wl *allowlist.Allowlist) (*plugin, *policyStore) {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	store := newPolicyStore(floorAllowlist(map[string]string{}))
	store.apply(wl, 1)
	return &plugin{
		cfg:      cfg,
		resolver: &ctrdresolver.Resolver{},
		policy:   store,
		audit:    audit.NewLogger(),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store
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

func TestCheckImage_ExemptNamespace_WithImage_Skips(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB // not in allowlist; exemption wins
	p, _ := newCachedPlugin(&config{Policy: policyConfig{
		Mode:             ModeFailClosed,
		ExemptNamespaces: []string{"kube-system"},
	}}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", imageRef, nil)
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
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

func TestCreateContainer_ImageFromPodAnnotation(t *testing.T) {
	// Container has no image annotation; falls back to the pod annotation.
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	pod.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestA}
	ctr := makeCtr(pod.Id, "myctr") // no annotations

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected pod-annotation fallback to resolve allowlisted digest, got: %v", err)
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

	// Should run the check without panicking or touching the (nil) resolver.
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

func TestRunDeferredCheck_ExemptNamespace_Skipped(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:             ModeFailClosed,
			EnforceExisting:  true,
			ExemptNamespaces: []string{"kube-system"},
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// Exempt namespace → checkLabels returns verdictSkip → check continues,
	// fail-closed mode but no kill because the container is skipped entirely.
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
	// resolver.StopContainer (nil containerd client → panic).
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
	if _, ok := p.inventory.containers[denied.Id]; ok {
		t.Fatal("denied container must not be recorded in the inventory")
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

func TestSynchronize_Ready_AuditMode_RunsCheck(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA) // allowed

	updates, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}
}

func TestSynchronize_EnforceExistingDisabled_ReturnsNil(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{}})
	p.SetReady()

	updates, err := p.Synchronize(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates when enforce_existing is disabled")
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
