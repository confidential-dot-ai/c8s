package nriimagepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// deadResolver returns a real containerd resolver whose socket nobody listens
// on: construction is lazy, every RPC fails fast with a connection error.
func deadResolver(t *testing.T) *ctrdresolver.Resolver {
	t.Helper()
	r, err := ctrdresolver.NewResolver(filepath.Join(t.TempDir(), "ctr.sock"), "k8s.io")
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// --- plugin.Run via a fake stub ---

// fakeStub embeds the Stub interface so only the methods plugin.Run touches
// need real implementations.
type fakeStub struct {
	stub.Stub
	stopped atomic.Bool
}

func (f *fakeStub) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeStub) Stop() { f.stopped.Store(true) }

func TestPluginRun_StopsOnContextCancel(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	fs := &fakeStub{}
	p.stub = fs

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Run(ctx) }()

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !fs.stopped.Load() {
		if time.Now().After(deadline) {
			t.Fatal("stub.Stop was not called on context cancellation")
		}
		time.Sleep(time.Millisecond)
	}
}

// --- RemoveContainer / Configure with inventory ---

func TestRemoveContainer_EvictsFromInventory(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.inventory = newAdmissionInventory(t.TempDir())
	p.inventory.record(cidApp1, "sandbox-1", "app", digestApp)

	ctr := &api.Container{Id: cidApp1, PodSandboxId: "sandbox-1", Name: "app"}
	if err := p.RemoveContainer(context.Background(), &api.PodSandbox{Id: "sandbox-1"}, ctr); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if _, ok := p.inventory.containers[cidApp1]; ok {
		t.Fatal("container not evicted from the inventory")
	}
}

func TestConfigure_InventoryAddsRemoveContainerMask(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.inventory = newAdmissionInventory(t.TempDir())

	mask, err := p.Configure(context.Background(), "", "containerd", "1.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want api.EventMask
	want.Set(api.Event_CREATE_CONTAINER)
	want.Set(api.Event_REMOVE_CONTAINER)
	// The inventory also needs the pod-sandbox lifecycle for its sandbox set.
	want.Set(api.Event_RUN_POD_SANDBOX)
	want.Set(api.Event_REMOVE_POD_SANDBOX)
	if mask != want {
		t.Fatalf("mask = %v, want %v", mask, want)
	}
}

// --- resolver-error paths (containerd socket nobody listens on) ---

func TestCheckImage_ResolveFails_Denies(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.resolver = deadResolver(t)

	// The containerd RPC blocks until the dial deadline; bound it so the
	// failure path is exercised without a multi-second wait.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	verdict, reason := p.checkImage(ctx, p.cfg, "default", "pod", "ctr", "registry/repo:latest", nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when digest resolution fails, got %d", verdict)
	}
	if !strings.Contains(reason, "cannot resolve digest") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestRecordForInventory_ResolveFails_RecordsEmptyDigest(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.resolver = deadResolver(t)
	p.inventory = newAdmissionInventory(t.TempDir())

	ctr := &api.Container{Id: "ctr-id", PodSandboxId: "sandbox-1", Name: "app"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.recordForInventory(ctx, ctr, "registry/repo:latest")

	rec, ok := p.inventory.containers["ctr-id"]
	if !ok {
		t.Fatal("container not recorded for the inventory")
	}
	if rec.digest != "" {
		t.Fatalf("recorded digest = %q, want empty (fail-closed at query time)", rec.digest)
	}
}
