package nriimagepolicy

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/nri/pkg/api"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// sealedPlugin is a plugin sealed to sealedDocument with a poweroff recorder.
func sealedPlugin(t *testing.T, cfg *config) (*plugin, *atomic.Int32) {
	t.Helper()
	doc, _ := sealedDocument(t)
	if cfg == nil {
		cfg = &config{Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true, DenyMissingAnnotation: true}}
	}
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		t.Fatal(err)
	}
	store := newPolicyStore(nil)
	store.apply(doc, 0)
	var calls atomic.Int32
	p := &plugin{
		cfg:        cfg,
		policy:     store,
		audit:      audit.NewLogger(),
		logger:     discardLogger(),
		containerd: &fakeContainerd{},
		sealed:     &sealedPolicy{doc: doc, hostIP: "10.0.0.7", nodeName: "node-a"},
		observer:   testObserver(),
		poweroff:   func() error { calls.Add(1); return nil },
	}
	return p, &calls
}

// webPod and webContainer are the pod and container the web rule admits.
func webPod() *api.PodSandbox {
	return &api.PodSandbox{Id: testSandboxID, Name: "web-0", Namespace: "tenant", Uid: testPodUID, Ips: []string{"10.42.0.9"}}
}

func webContainer(image string) *api.Container {
	podRoot := allowlist.KubeletVolumesRoot + testPodUID + "/"
	return &api.Container{
		Id: "web-ctr", PodSandboxId: testSandboxID, Name: "app",
		Annotations: map[string]string{annotationImageName: image},
		Args:        []string{"/app", "serve"},
		Env:         []string{"PATH=/bin", "POD_NAME=web-0", "NODE=node-a"},
		Mounts: []*api.Mount{
			sysfsMount("nosuid", "noexec", "nodev", "ro"),
			bind("/etc/hosts", podRoot+"etc-hosts"),
			bind("/data", podRoot+"volumes/kubernetes.io~empty-dir/data"),
			bind("/var/run/secrets/kubernetes.io/serviceaccount", podRoot+"volumes/kubernetes.io~projected/kube-api-access-abc"),
		},
		Linux: &api.LinuxContainer{Namespaces: ownNamespaces()},
	}
}

// webSpec is the stored OCI spec of an admitted web container.
func webSpec() *oci.Spec {
	bounding := []string{"CAP_CHOWN", "CAP_KILL"}
	return &oci.Spec{
		Mounts:  []specs.Mount{{Destination: "/sys", Type: "sysfs", Options: []string{"ro"}}},
		Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: bounding}, NoNewPrivileges: true},
		Linux:   &specs.Linux{MaskedPaths: []string{"/proc/kcore"}},
	}
}

func specReturning(spec *oci.Spec, err error) func(context.Context, string) (*oci.Spec, error) {
	return func(context.Context, string) (*oci.Spec, error) { return spec, err }
}

func TestSealedCreateContainer(t *testing.T) {
	image := "registry/web@" + pushDigestA
	for _, tc := range []struct {
		name    string
		pod     func() *api.PodSandbox
		ctr     func() *api.Container
		cfg     *config
		wantErr string
	}{
		{"admitted", webPod, func() *api.Container { return webContainer(image) }, nil, ""},
		{"no annotation", webPod, func() *api.Container { return webContainer("") }, nil, "no image annotation"},
		{"unlisted digest", webPod, func() *api.Container { return webContainer("registry/web@" + pushDigestC) }, nil, "not admitted by the sealed allowlist"},
		{"argv drift", webPod, func() *api.Container {
			c := webContainer(image)
			c.Args = append(c.Args, "--debug")
			return c
		}, nil, "not admitted"},
		{"env value drift", webPod, func() *api.Container {
			c := webContainer(image)
			c.Env[0] = "PATH=/bin:/evil"
			return c
		}, nil, "not admitted"},
		{"from-source drift", func() *api.PodSandbox {
			p := webPod()
			p.Name = "web-1"
			return p
		}, func() *api.Container { return webContainer(image) }, nil, "not admitted"},
		{"configMap mount", webPod, func() *api.Container {
			c := webContainer(image)
			c.Mounts = append(c.Mounts, bind("/etc/app", allowlist.KubeletVolumesRoot+testPodUID+"/volumes/kubernetes.io~configmap/cfg"))
			return c
		}, nil, "not admitted"},
		{"host pid namespace", webPod, func() *api.Container {
			c := webContainer(image)
			c.Linux.Namespaces = []*api.LinuxNamespace{{Type: "network"}, {Type: "ipc"}}
			return c
		}, nil, "not admitted"},
		{"hooks", webPod, func() *api.Container {
			c := webContainer(image)
			c.Hooks = &api.Hooks{Prestart: []*api.Hook{{Path: "/hook"}}}
			return c
		}, nil, "not admitted"},
		{"device", webPod, func() *api.Container {
			c := webContainer(image)
			c.Linux.Devices = []*api.LinuxDevice{{Path: "/dev/kvm"}}
			return c
		}, nil, "not admitted"},
		{"privileged", webPod, func() *api.Container {
			c := webContainer(image)
			c.Mounts[0] = sysfsMount("nosuid")
			return c
		}, nil, "not admitted"},
		{"label rule denies first", webPod, func() *api.Container { return webContainer(image) },
			&config{Policy: policyConfig{Mode: ModeFailClosed, LabelRules: []labelRule{{Name: "tenant",
				MatchExpressions: []labelExpression{{Key: "tenant", Operator: OpExists}}}}}}, `label rule "tenant" denied`},
		{"audit mode does not pass through", webPod, func() *api.Container { return webContainer("registry/web@" + pushDigestC) },
			&config{Policy: policyConfig{Mode: ModeAudit}}, "not admitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := sealedPlugin(t, tc.cfg)
			_, _, err := p.CreateContainer(context.Background(), tc.pod(), tc.ctr())
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("CreateContainer(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "--debug") {
				t.Fatalf("CreateContainer(%s) error %q leaks argv", tc.name, err)
			}
		})
	}
}

func TestSealedCreateContainer_PrivilegedEntry(t *testing.T) {
	p, _ := sealedPlugin(t, nil)
	pod := &api.PodSandbox{Id: testSandboxID, Name: "cni-x", Namespace: "kube-system", Uid: testPodUID}
	ctr := &api.Container{
		Id: "cni", PodSandboxId: testSandboxID, Name: "agent",
		Annotations: map[string]string{annotationImageName: "registry/cni@" + pushDigestB},
		Args:        []string{"/agent"},
		Env:         []string{"PATH=/bin"},
		Mounts:      []*api.Mount{sysfsMount("nosuid"), bind("/host/modules", "/lib/modules/6.12/kernel")},
		Linux: &api.LinuxContainer{Namespaces: []*api.LinuxNamespace{{Type: "pid"}, {Type: "ipc"}},
			Devices: []*api.LinuxDevice{{Path: "/dev/kvm"}}},
	}
	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
		t.Fatalf("CreateContainer(privileged entry) = %v, want admitted", err)
	}
	ctr.Mounts = append(ctr.Mounts, bind("/host/etc", "/etc"))
	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("CreateContainer(privileged entry, hostPath outside hostPaths) admitted")
	}
	ctr.Mounts = ctr.Mounts[:2]
	ctr.Args = []string{"/bin/sh", "-c", "id"}
	if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("CreateContainer(privileged entry, other argv) admitted: a privileged image with an open argv is a shell on the node")
	}
}

func TestSealedCreateContainer_ResolvesTags(t *testing.T) {
	p, _ := sealedPlugin(t, nil)
	fake := p.containerd.(*fakeContainerd)
	fake.resolve = func(_ context.Context, ref string) (string, error) {
		if ref != "registry/web:v1" {
			t.Fatalf("Resolve(%q), want registry/web:v1", ref)
		}
		return pushDigestA, nil
	}
	if _, _, err := p.CreateContainer(context.Background(), webPod(), webContainer("registry/web:v1")); err != nil {
		t.Fatalf("CreateContainer(tag) = %v, want admitted through resolution", err)
	}
	fake.resolve = func(context.Context, string) (string, error) { return "", errors.New("not pulled") }
	if _, _, err := p.CreateContainer(context.Background(), webPod(), webContainer("registry/web:v1")); err == nil || !strings.Contains(err.Error(), "cannot resolve digest") {
		t.Fatalf("CreateContainer(unresolvable tag) = %v, want a resolve denial", err)
	}
}

func TestSealedCreateContainer_RecordsForInventory(t *testing.T) {
	p, _ := sealedPlugin(t, nil)
	p.inventory = newAdmissionInventory(t.TempDir())
	if _, _, err := p.CreateContainer(context.Background(), webPod(), webContainer("registry/web@"+pushDigestA)); err != nil {
		t.Fatal(err)
	}
	if rec, ok := p.inventory.containers["web-ctr"]; !ok || rec.digest != pushDigestA {
		t.Fatalf("inventory record = %+v, %v; want digest %s", rec, ok, pushDigestA)
	}
	if _, _, err := p.CreateContainer(context.Background(), webPod(), webContainer("registry/web@"+pushDigestC)); err == nil {
		t.Fatal("denied container admitted")
	}
	if len(p.inventory.containers) != 1 {
		t.Fatalf("denied container recorded: %d records", len(p.inventory.containers))
	}
}

// A check that admits after the deadline describes a container the runtime
// never created (it heard the deny), so the inventory must not record it.
func TestSealedCreateContainer_LateAdmissionIsNotRecorded(t *testing.T) {
	prev := sealedHookTimeout
	sealedHookTimeout = 20 * time.Millisecond
	t.Cleanup(func() { sealedHookTimeout = prev })

	p, _ := sealedPlugin(t, nil)
	p.inventory = newAdmissionInventory(t.TempDir())
	release := make(chan struct{})
	resolved := make(chan struct{}, 2)
	p.containerd.(*fakeContainerd).resolve = func(context.Context, string) (string, error) {
		<-release
		resolved <- struct{}{}
		return pushDigestA, nil
	}
	_, _, err := p.CreateContainer(context.Background(), webPod(), webContainer("registry/web:v1"))
	if err == nil || !strings.Contains(err.Error(), "CreateContainer did not complete within") {
		t.Fatalf("CreateContainer(slow resolve) = %v, want a timeout denial", err)
	}
	close(release)
	<-resolved
	// The late check admits right after resolving; give it time to act.
	time.Sleep(50 * time.Millisecond)
	if n := len(p.inventory.containers); n != 0 {
		t.Fatalf("late admission recorded %d containers, want 0", n)
	}
}

func TestSealedHooks_TimeoutDenies(t *testing.T) {
	prev := sealedHookTimeout
	sealedHookTimeout = 20 * time.Millisecond
	t.Cleanup(func() { sealedHookTimeout = prev })

	p, _ := sealedPlugin(t, nil)
	fake := p.containerd.(*fakeContainerd)
	fake.resolve = func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	fake.spec = func(ctx context.Context, _ string) (*oci.Spec, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	pod, ctr := webPod(), webContainer("registry/web:v1")
	start := time.Now()
	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil || !strings.Contains(err.Error(), "CreateContainer did not complete within") {
		t.Fatalf("CreateContainer(slow resolve) = %v, want a timeout denial", err)
	}
	if err := p.StartContainer(context.Background(), pod, webContainer("registry/web@"+pushDigestA)); err == nil || !strings.Contains(err.Error(), "StartContainer did not complete within") {
		t.Fatalf("StartContainer(slow spec) = %v, want a timeout denial", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("hooks took %s, want well under the runtime's 2s", elapsed)
	}
}

func TestSealedPostCreateAndStart(t *testing.T) {
	image := "registry/web@" + pushDigestA
	privileged := webSpec()
	privileged.Mounts[0].Options = nil
	extraCaps := webSpec()
	extraCaps.Process.Capabilities.Bounding = append(extraCaps.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
	unmasked := webSpec()
	unmasked.Linux.MaskedPaths = nil
	for _, tc := range []struct {
		name    string
		spec    *oci.Spec
		specErr error
		wantErr string
	}{
		{"spec matches", webSpec(), nil, ""},
		{"spec adds a capability", extraCaps, nil, "not admitted"},
		{"spec is privileged", privileged, nil, "not admitted"},
		{"spec unmasks proc", unmasked, nil, "not admitted"},
		{"spec cannot be loaded", nil, errors.New("gone"), "cannot load the OCI spec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := sealedPlugin(t, nil)
			fake := p.containerd.(*fakeContainerd)
			loads := 0
			fake.spec = func(context.Context, string) (*oci.Spec, error) { loads++; return tc.spec, tc.specErr }
			pod, ctr := webPod(), webContainer(image)

			postErr := p.PostCreateContainer(context.Background(), pod, ctr)
			startErr := p.StartContainer(context.Background(), pod, ctr)
			if (tc.wantErr == "") != (startErr == nil) || (startErr != nil && !strings.Contains(startErr.Error(), tc.wantErr)) {
				t.Fatalf("StartContainer(%s) = %v, want error containing %q", tc.name, startErr, tc.wantErr)
			}
			if (postErr == nil) != (startErr == nil) {
				t.Fatalf("PostCreateContainer(%s) = %v but StartContainer = %v", tc.name, postErr, startErr)
			}
			if loads != 1 {
				t.Fatalf("StartContainer(%s) loaded the spec again: %d loads, want the cached verdict", tc.name, loads)
			}

			// Eviction forgets the verdict; the next start re-evaluates.
			if err := p.RemoveContainer(context.Background(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			if _, ok := p.verdicts.get(ctr.GetId()); ok {
				t.Fatal("RemoveContainer left the verdict cached")
			}
			if err := p.StartContainer(context.Background(), pod, ctr); loads != 2 || (err == nil) != (startErr == nil) {
				t.Fatalf("StartContainer(%s) after eviction = %v with %d loads, want a re-evaluation", tc.name, err, loads)
			}
		})
	}
}

func TestSealedPostCreateAndStart_DenyIsCachedNotRecomputed(t *testing.T) {
	p, _ := sealedPlugin(t, nil)
	fake := p.containerd.(*fakeContainerd)
	fake.spec = specReturning(webSpec(), nil)
	pod, ctr := webPod(), webContainer("registry/web@"+pushDigestC)
	if err := p.PostCreateContainer(context.Background(), pod, ctr); err == nil {
		t.Fatal("PostCreateContainer admitted an unlisted digest")
	}
	// A container whose message changed after create still gets the cached
	// deny: the verdict follows the ID.
	if err := p.StartContainer(context.Background(), pod, webContainer("registry/web@"+pushDigestA)); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("StartContainer(cached deny) = %v, want the cached denial", err)
	}
}

func TestSealedHooks_DynamicPluginIsUntouched(t *testing.T) {
	p := floorPlugin(t)
	if err := p.PostCreateContainer(context.Background(), webPod(), webContainer("x")); err != nil {
		t.Fatalf("PostCreateContainer(dynamic) = %v, want nil", err)
	}
	if err := p.StartContainer(context.Background(), webPod(), webContainer("x")); err != nil {
		t.Fatalf("StartContainer(dynamic) = %v, want nil", err)
	}
}

func TestSealedSynchronize(t *testing.T) {
	t.Run("no containers seeds the inventory", func(t *testing.T) {
		p, calls := sealedPlugin(t, nil)
		p.inventory = newAdmissionInventory(t.TempDir())
		if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{webPod()}, nil); err != nil {
			t.Fatalf("Synchronize(no containers) = %v, want nil", err)
		}
		if _, _, known, _ := p.inventory.DigestsForSandbox(testSandboxID); !known {
			t.Fatal("sandbox not seeded")
		}
		if calls.Load() != 0 {
			t.Fatal("powered off with no containers")
		}
	})
	t.Run("a running container powers the node off", func(t *testing.T) {
		p, calls := sealedPlugin(t, nil)
		_, err := p.Synchronize(context.Background(), []*api.PodSandbox{webPod()}, []*api.Container{webContainer("registry/web@" + pushDigestA)})
		if !errors.Is(err, errSealedFatal) {
			t.Fatalf("Synchronize(running container) = %v, want errSealedFatal", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("poweroff called %d times, want 1", calls.Load())
		}
	})
	t.Run("power-off failure still returns the fatal error", func(t *testing.T) {
		p, _ := sealedPlugin(t, nil)
		p.poweroff = func() error { return errors.New("no systemd") }
		if _, err := p.Synchronize(context.Background(), nil, []*api.Container{webContainer("x")}); !errors.Is(err, errSealedFatal) {
			t.Fatalf("Synchronize(orphan container, poweroff fails) = %v, want errSealedFatal", err)
		}
	})
}

func TestSealedConfigure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		require   bool
		version   string
		inventory bool
		wantErr   bool
	}{
		{"marker not required", false, "v2.3.4", false, false},
		{"marker required and present", true, "v2.3.4+c8s.nri-failclosed", false, false},
		{"marker required and absent", true, "v2.3.4", false, true},
		{"marker required, inventory on", true, "v2.3.4+c8s.nri-failclosed.1", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := sealedPlugin(t, &config{Runtime: runtimeConfig{RequireFailClosed: tc.require}, Policy: policyConfig{Mode: ModeFailClosed}})
			if tc.inventory {
				p.inventory = newAdmissionInventory(t.TempDir())
			}
			mask, err := p.Configure(context.Background(), "", "containerd", tc.version)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Configure(%s) = %v, want error %v", tc.name, err, tc.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), FailClosedRuntimeMarker) {
					t.Fatalf("Configure(%s) error %q does not name the marker", tc.name, err)
				}
				return
			}
			for _, ev := range []api.Event{api.Event_CREATE_CONTAINER, api.Event_POST_CREATE_CONTAINER, api.Event_START_CONTAINER, api.Event_REMOVE_CONTAINER} {
				if !mask.IsSet(ev) {
					t.Errorf("Configure(%s) did not subscribe %s", tc.name, ev)
				}
			}
			if mask.IsSet(api.Event_RUN_POD_SANDBOX) != tc.inventory {
				t.Errorf("Configure(%s) pod-sandbox subscription = %v, want %v", tc.name, mask.IsSet(api.Event_RUN_POD_SANDBOX), tc.inventory)
			}
		})
	}
}

func TestVerdictCache(t *testing.T) {
	var c verdictCache
	if _, ok := c.get("a"); ok {
		t.Fatal("empty cache answered")
	}
	c.put("a", sealedVerdict{denied: true, reason: "no"})
	c.put("b", sealedVerdict{})
	if v, ok := c.get("a"); !ok || !v.denied || v.reason != "no" {
		t.Fatalf("get(a) = %+v, %v; want the stored deny", v, ok)
	}
	c.drop("a")
	c.drop("never-stored")
	if _, ok := c.get("a"); ok {
		t.Fatal("drop(a) left the verdict")
	}
	if v, ok := c.get("b"); !ok || v.denied {
		t.Fatalf("get(b) = %+v, %v; want the stored allow", v, ok)
	}
}
