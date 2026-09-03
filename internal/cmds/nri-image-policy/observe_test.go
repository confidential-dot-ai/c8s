package nriimagepolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/nri/pkg/api"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

const (
	testPlatformDir  = "/run/nri-image-policy"
	testSandboxState = "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/" + testSandboxID + "/"
)

func testObserver() observer {
	return observer{platformDir: testPlatformDir, hostIP: "10.0.0.7", nodeName: "node-a"}
}

func bind(dest, src string) *api.Mount {
	return &api.Mount{Destination: dest, Type: "bind", Source: src, Options: []string{"rbind", "rprivate", "rw"}}
}

// ownNamespaces are the namespaces a pod container gets with no host sharing.
func ownNamespaces() []*api.LinuxNamespace {
	return []*api.LinuxNamespace{
		{Type: "network", Path: "/var/run/netns/cni-1"}, {Type: "pid"}, {Type: "ipc", Path: "/proc/1/ns/ipc"},
		{Type: "uts", Path: "/proc/1/ns/uts"}, {Type: "mount"},
	}
}

func sysfsMount(options ...string) *api.Mount {
	return &api.Mount{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: options}
}

func TestClassify(t *testing.T) {
	podRoot := allowlist.KubeletVolumesRoot + testPodUID + "/"
	for _, tc := range []struct {
		name, source, want string
	}{
		{"emptyDir", podRoot + "volumes/kubernetes.io~empty-dir/scratch", allowlist.SourceEmptyDir},
		{"memory emptyDir", podRoot + "volumes/kubernetes.io~empty-dir/c8s-certs", allowlist.SourceEmptyDir},
		{"service account token", podRoot + "volumes/kubernetes.io~projected/kube-api-access-x7z9q", allowlist.SourceServiceAccountToken},
		{"other projected", podRoot + "volumes/kubernetes.io~projected/certs", "projected"},
		{"csi pvc", podRoot + "volumes/kubernetes.io~csi/pvc-1/mount", allowlist.SourcePVC},
		{"local pv", podRoot + "volumes/kubernetes.io~local-volume/pv-1", allowlist.SourcePVC},
		{"local-path pv", localPathProvisionerRoot + "pvc-1_default_data", allowlist.SourcePVC},
		{"configMap", podRoot + "volumes/kubernetes.io~configmap/cfg", "configMap"},
		{"secret", podRoot + "volumes/kubernetes.io~secret/tls", "secret"},
		{"downwardAPI", podRoot + "volumes/kubernetes.io~downward-api/info", "downwardAPI"},
		{"unknown kubelet plugin", podRoot + "volumes/kubernetes.io~nfs/share", "nfs"},
		{"kubelet etc-hosts", podRoot + "etc-hosts", allowlist.SourcePlatform},
		{"termination log", podRoot + "containers/app/1a2b3c", allowlist.SourcePlatform},
		{"cri hostname", testSandboxState + "hostname", allowlist.SourcePlatform},
		{"cri resolv.conf", testSandboxState + "resolv.conf", allowlist.SourcePlatform},
		{"cri shm", testSandboxState + "shm", allowlist.SourcePlatform},
		{"another sandbox's shm", "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/other/shm", allowlist.SourceHostPath},
		{"plugin socket dir", testPlatformDir, allowlist.SourcePlatform},
		{"plugin socket dir file", testPlatformDir + "/inventory.sock", allowlist.SourcePlatform},
		{"plugin socket dir sibling", testPlatformDir + "-evil/x", allowlist.SourceHostPath},
		{"node state dir", policybundle.NodeStateDir, allowlist.SourceNodeState},
		{"attestation socket", policybundle.NodeStateDir + "/attestation-api.sock", allowlist.SourceNodeState},
		{"policy dir member", policybundle.DefaultPolicyDir + "/static-allowlist.json", allowlist.SourceNodeState},
		{"node state dir sibling", policybundle.NodeStateDir + "-evil/attestation-api.sock", allowlist.SourceHostPath},
		{"another pod's emptyDir", allowlist.KubeletVolumesRoot + "other-uid/volumes/kubernetes.io~empty-dir/x", allowlist.SourceHostPath},
		{"pod dir outside volumes", podRoot + "plugins/x", allowlist.SourceHostPath},
		{"host path", "/lib/modules", allowlist.SourceHostPath},
		{"host dev shm", "/dev/shm", allowlist.SourceHostPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := testObserver().classify(tc.source, testPodUID, testSandboxID, false); got != tc.want {
				t.Fatalf("classify(%s) = %q, want %q", tc.source, got, tc.want)
			}
		})
	}
	t.Run("no pod uid classifies kubelet volumes as hostPath", func(t *testing.T) {
		if got := testObserver().classify(podRoot+"volumes/kubernetes.io~empty-dir/x", "", testSandboxID, false); got != allowlist.SourceHostPath {
			t.Fatalf("classify(emptyDir, no uid) = %q, want hostPath", got)
		}
	})
	// containerd binds the node's /dev/shm for a pod that shares the node's
	// IPC namespace; render emits a platform rule for it, like the sandbox's.
	for _, tc := range []struct {
		name, source, want string
	}{
		{"host dev shm under host ipc", "/dev/shm", allowlist.SourcePlatform},
		{"path under host dev shm under host ipc", "/dev/shm/x", allowlist.SourceHostPath},
		{"host path under host ipc", "/lib/modules", allowlist.SourceHostPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := testObserver().classify(tc.source, testPodUID, testSandboxID, true); got != tc.want {
				t.Fatalf("classify(%s, hostIPC) = %q, want %q", tc.source, got, tc.want)
			}
		})
	}
}

// The rule render emits for a pod with hostIPC (a platform rule for /dev/shm
// plus the ipc host namespace) must admit what containerd binds for it: the
// node's /dev/shm, with no ipc namespace entry in the spec.
func TestObserve_HostIPCShmAdmittedByRenderedRule(t *testing.T) {
	rule := allowlist.Container{
		Digest:  mustDigest(t, pushDigestA),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/app"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"serve"}},
		Env: allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"PATH"},
			Values: map[string]allowlist.EnvValue{"PATH": {Value: str("/bin")}}},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Destinations: []string{"/dev/shm"},
			Rules: map[string]allowlist.MountRule{"/dev/shm": {Source: allowlist.SourcePlatform}}},
		Privileges: &allowlist.Privileges{HostNamespaces: []string{allowlist.HostNamespaceIPC}, Review: "shares the node's IPC namespace"},
	}
	raw, err := json.Marshal(&allowlist.Allowlist{Schema: allowlist.Schema, Digests: map[string]string{},
		Workloads: map[string]allowlist.Workload{"shm": {Containers: []allowlist.Container{rule}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := allowlist.LintSealed(mustCanonical(t, raw)); err != nil {
		t.Fatalf("rendered-shape rule is not sealed: %v", err)
	}
	doc, err := allowlist.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	index := doc.BuildIndex()

	container := func(namespaces []*api.LinuxNamespace) *api.Container {
		return &api.Container{
			Id: "shm-ctr", PodSandboxId: testSandboxID, Name: "app",
			Args:   []string{"/app", "serve"},
			Env:    []string{"PATH=/bin"},
			Mounts: []*api.Mount{sysfsMount("ro"), bind("/dev/shm", "/dev/shm")},
			Linux:  &api.LinuxContainer{Namespaces: namespaces},
		}
	}
	withoutIPC := []*api.LinuxNamespace{{Type: "network", Path: "/var/run/netns/cni-1"}, {Type: "pid"}, {Type: "uts"}, {Type: "mount"}}
	pod := &api.PodSandbox{Id: testSandboxID, Name: "shm-0", Namespace: "tenant", Uid: testPodUID}
	if _, ok := index.Admit(testObserver().observe(pod, container(withoutIPC), pushDigestA)); !ok {
		t.Fatal("Admit(hostIPC container) = false, want the rendered platform rule to admit the node's /dev/shm")
	}
	if _, ok := index.Admit(testObserver().observe(pod, container(ownNamespaces()), pushDigestA)); ok {
		t.Fatal("Admit(own-IPC container binding the node's /dev/shm) = true, want a deny")
	}
}

func mustCanonical(t *testing.T, raw []byte) []byte {
	t.Helper()
	doc, err := allowlist.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestObserve(t *testing.T) {
	podRoot := allowlist.KubeletVolumesRoot + testPodUID + "/"
	pod := &api.PodSandbox{Id: testSandboxID, Name: "web-0", Namespace: "tenant", Uid: testPodUID, Ips: []string{"10.42.0.9", "fd00::9"}}
	ctr := &api.Container{
		Id: "ctr-1", PodSandboxId: testSandboxID, Name: "app",
		Args: []string{"/app", "serve"},
		Env:  []string{"PATH=/bin", "EMPTY=", "NOEQ", "KEY=a=b"},
		Mounts: []*api.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			sysfsMount("nosuid", "noexec", "nodev", "ro"),
			bind("/etc/hosts", podRoot+"etc-hosts"),
			bind("/data/", podRoot+"volumes/kubernetes.io~empty-dir/data"),
			bind("/run/c8s/workload-claims", "/var/run/nri-image-policy"),
			bind("/host/modules", "/lib/modules/"),
		},
		Linux: &api.LinuxContainer{
			Namespaces: []*api.LinuxNamespace{{Type: "network", Path: "/var/run/netns/x"}, {Type: "uts"}, {Type: "mount"}},
			Devices:    []*api.LinuxDevice{{Path: "/dev/nvidia0"}, {Path: "/dev/kvm"}, {Path: "/dev/nvidiactl"}},
		},
		CDIDevices: []*api.CDIDevice{{Name: "nvidia.com/gpu=0"}},
	}
	o := testObserver()
	o.cdiDeviceNodes = func(names []string) ([]string, error) {
		if !reflect.DeepEqual(names, []string{"nvidia.com/gpu=0"}) {
			t.Fatalf("cdiDeviceNodes(%v), want [nvidia.com/gpu=0]", names)
		}
		return []string{"/dev/nvidia0", "/dev/nvidiactl"}, nil
	}

	got := o.observe(pod, ctr, pushDigestA)
	want := allowlist.Observation{
		Digest: pushDigestA,
		Argv:   []string{"/app", "serve"},
		Env:    map[string]string{"PATH": "/bin", "EMPTY": "", "NOEQ": "", "KEY": "a=b"},
		Mounts: map[string]allowlist.MountSource{
			"/etc/hosts":               {Path: podRoot + "etc-hosts", Class: allowlist.SourcePlatform},
			"/data":                    {Path: podRoot + "volumes/kubernetes.io~empty-dir/data", Class: allowlist.SourceEmptyDir},
			"/run/c8s/workload-claims": {Path: "/run/nri-image-policy", Class: allowlist.SourcePlatform},
			"/host/modules":            {Path: "/lib/modules", Class: allowlist.SourceHostPath},
		},
		HostNamespaces: []string{allowlist.HostNamespaceIPC, allowlist.HostNamespacePID},
		Devices:        []string{"/dev/kvm"},
		Sources: map[string]string{
			allowlist.FromPodIP: "10.42.0.9", allowlist.FromPodName: "web-0", allowlist.FromPodNamespace: "tenant",
			allowlist.FromPodUID: testPodUID, allowlist.FromHostIP: "10.0.0.7", allowlist.FromNodeName: "node-a",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observe() = %+v\nwant %+v", got, want)
	}

	t.Run("cdi lookup failure leaves every device unexplained", func(t *testing.T) {
		o.cdiDeviceNodes = func([]string) ([]string, error) { return nil, errors.New("no specs") }
		if got := o.observe(pod, ctr, pushDigestA).Devices; !reflect.DeepEqual(got, []string{"/dev/kvm", "/dev/nvidia0", "/dev/nvidiactl"}) {
			t.Fatalf("Devices = %v, want all three", got)
		}
	})
	t.Run("no ips leaves podIP unset", func(t *testing.T) {
		if _, ok := o.observe(&api.PodSandbox{}, ctr, pushDigestA).Sources[allowlist.FromPodIP]; ok {
			t.Fatal("podIP present for a sandbox without IPs")
		}
	})
	t.Run("hooks, writable sysfs and full namespaces", func(t *testing.T) {
		c := &api.Container{
			Mounts: []*api.Mount{sysfsMount("nosuid", "noexec", "nodev")},
			Hooks:  &api.Hooks{CreateRuntime: []*api.Hook{{Path: "/usr/bin/nvidia-cdi-hook"}}},
			Linux:  &api.LinuxContainer{Namespaces: ownNamespaces()},
		}
		got := o.observe(pod, c, pushDigestA)
		if !got.Hooks || !got.Privileged || got.HostNamespaces != nil {
			t.Fatalf("observe(hooks, rw sysfs) = hooks %v, privileged %v, host namespaces %v; want true, true, none", got.Hooks, got.Privileged, got.HostNamespaces)
		}
	})
}

func TestObserveSpec(t *testing.T) {
	ro := specs.Mount{Destination: "/sys", Type: "sysfs", Options: []string{"ro"}}
	rw := specs.Mount{Destination: "/sys", Type: "sysfs", Options: []string{"rw"}}
	caps := func(extra ...string) *specs.LinuxCapabilities {
		bounding := append([]string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_BIND_SERVICE"}, extra...)
		return &specs.LinuxCapabilities{Bounding: bounding, Effective: bounding, Permitted: bounding}
	}
	for _, tc := range []struct {
		name string
		spec *oci.Spec
		want allowlist.Observation
	}{
		{"ordinary", &oci.Spec{Mounts: []specs.Mount{ro}, Process: &specs.Process{Capabilities: caps()},
			Linux: &specs.Linux{MaskedPaths: []string{"/proc/kcore"}}}, allowlist.Observation{}},
		{"added capabilities", &oci.Spec{Mounts: []specs.Mount{ro}, Process: &specs.Process{Capabilities: caps("CAP_SYS_ADMIN", "CAP_NET_ADMIN")},
			Linux: &specs.Linux{MaskedPaths: []string{"/proc/kcore"}}}, allowlist.Observation{Capabilities: []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"}}},
		{"unmasked proc", &oci.Spec{Mounts: []specs.Mount{ro}, Process: &specs.Process{Capabilities: caps()}, Linux: &specs.Linux{}},
			allowlist.Observation{UnmaskedProc: true}},
		{"privileged", &oci.Spec{Mounts: []specs.Mount{rw}, Process: &specs.Process{Capabilities: caps("CAP_SYS_ADMIN")}, Linux: &specs.Linux{}},
			allowlist.Observation{Privileged: true, Capabilities: []string{"CAP_SYS_ADMIN"}}},
		{"no process block", &oci.Spec{Mounts: []specs.Mount{ro}, Linux: &specs.Linux{MaskedPaths: []string{"/proc/kcore"}}}, allowlist.Observation{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observeSpec(allowlist.Observation{Capabilities: []string{"stale"}}, tc.spec)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("observeSpec(%s) = %+v, want %+v", tc.name, got, tc.want)
			}
		})
	}
}

func TestSpecSecurity(t *testing.T) {
	got := specSecurity(&oci.Spec{Process: &specs.Process{NoNewPrivileges: true},
		Linux: &specs.Linux{Seccomp: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}}})
	if want := []any{"seccomp", "SCMP_ACT_ERRNO", "no_new_privileges", true}; !reflect.DeepEqual(got, want) {
		t.Fatalf("specSecurity(confined) = %v, want %v", got, want)
	}
	if got := specSecurity(&oci.Spec{}); !reflect.DeepEqual(got, []any{"seccomp", "unconfined", "no_new_privileges", false}) {
		t.Fatalf("specSecurity(empty) = %v, want unconfined, false", got)
	}
}

func TestRunPath(t *testing.T) {
	for in, want := range map[string]string{
		"/var/run/nri-image-policy/": "/run/nri-image-policy",
		"/var/run":                   "/run",
		"/var/runner/x":              "/var/runner/x",
		"/lib/modules/../modules":    "/lib/modules",
	} {
		if got := runPath(in); got != want {
			t.Errorf("runPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCDIDeviceNodesFrom(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("nvidia.yaml", `
cdiVersion: 0.6.0
kind: nvidia.com/gpu
containerEdits:
  deviceNodes:
    - path: /dev/nvidiactl
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
  - name: all
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
        - path: /dev/nvidia1
`)
	write("vfio.json", `{"cdiVersion":"0.6.0","kind":"example.com/vfio","devices":[{"name":"a","containerEdits":{"deviceNodes":[{"path":"/dev/vfio/1"}]}}]}`)
	write("README.txt", "not a spec")
	resolve := cdiDeviceNodesFrom([]string{dir, filepath.Join(dir, "absent")})
	for _, tc := range []struct {
		name    string
		names   []string
		want    []string
		wantErr string
	}{
		{"gpu 0 with kind-level edits", []string{"nvidia.com/gpu=0"}, []string{"/dev/nvidiactl", "/dev/nvidia0"}, ""},
		{"two devices", []string{"nvidia.com/gpu=all", "example.com/vfio=a"}, []string{"/dev/nvidiactl", "/dev/nvidia0", "/dev/nvidia1", "/dev/vfio/1"}, ""},
		{"unknown device", []string{"nvidia.com/gpu=9"}, nil, "in no spec"},
		{"malformed name", []string{"nvidia.com/gpu"}, nil, "not <kind>=<name>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolve(tc.names)
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("cdiDeviceNodes(%v) = %v, want error containing %q", tc.names, err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("cdiDeviceNodes(%v) = %v, want %v", tc.names, got, tc.want)
			}
		})
	}
	t.Run("malformed spec file is an error", func(t *testing.T) {
		write("broken.yaml", "kind: [")
		if _, err := resolve([]string{"nvidia.com/gpu=0"}); err == nil || !strings.Contains(err.Error(), "parse CDI spec broken.yaml") {
			t.Fatalf("cdiDeviceNodes(broken spec dir) = %v, want a parse error", err)
		}
	})
}
