package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/lunal-dev/c8s/internal/audit"
	"github.com/lunal-dev/c8s/internal/cache"
)

func newTestPlugin(cfg *Config) *Plugin {
	return &Plugin{
		cfg:    cfg,
		audit:  audit.NewLogger(),
		logger: slog.Default(),
	}
}

func TestCheckImage_MissingAnnotation_DenyEnabled(t *testing.T) {
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
			DenyMissingAnnotation: true,
		},
	})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", "")
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != "container has no image annotation" {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckImage_MissingAnnotation_DenyDisabled(t *testing.T) {
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
			DenyMissingAnnotation: false,
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", "")
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip, got %d", verdict)
	}
}

func TestCheckImage_MissingAnnotation_ExemptNamespace(t *testing.T) {
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", "")
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
	}
}

func TestCheckImage_NonExemptSystemNamespace(t *testing.T) {
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-node-lease", "pod", "ctr", "")
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

func TestCreateContainer_NotReady_DenyNonExempt(t *testing.T) {
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
			Mode:             "fail-closed",
			ExemptNamespaces: []string{"kube-system"},
		},
	})
	// Plugin is NOT ready (default zero value of atomic.Bool is false)

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
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
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
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
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
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
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
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
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

func TestRunDeferredSweep_NothingDeferred(t *testing.T) {
	p := newTestPlugin(&Config{
		Policy: PolicyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})
	p.SetReady()

	// Should be a no-op without panic
	p.RunDeferredSweep(context.Background())
}

func TestCreateContainer_Ready_PassesThrough(t *testing.T) {
	policyCache := cache.NewPolicyCache()
	p := &Plugin{
		cfg: &Config{
			Policy: PolicyConfig{
				Mode:                  "fail-closed",
				DenyMissingAnnotation: true,
				ExemptNamespaces:      []string{"kube-system"},
			},
		},
		audit:  audit.NewLogger(),
		logger: slog.Default(),
		cache:  policyCache,
	}
	p.SetReady()

	// Container with no image annotation and deny_missing_annotation=true
	// should go through the normal path and be denied (not the init guard).
	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from normal whitelist check path")
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
