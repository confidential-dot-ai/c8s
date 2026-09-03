package nriimagepolicy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/nri/pkg/api"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

// criSandboxDir is the path segment under containerd's state directory
// where the CRI keeps a sandbox's hostname, resolv.conf and shm: the
// sources of the binds it adds to every container.
const criSandboxDir = "/io.containerd.grpc.v1.cri/sandboxes/"

// localPathProvisionerRoot is where local-path-storage keeps hostPath-type
// persistent volumes on the node image (local-path-storage.yaml).
const localPathProvisionerRoot = "/opt/local-path-provisioner/"

// hostDevShm is the bind source containerd's CRI uses for /dev/shm when the
// pod shares the node's IPC namespace (container_create.go: NamespaceMode_NODE).
const hostDevShm = "/dev/shm"

// defaultCDISpecDirs are where the CDI registry reads device specs from.
var defaultCDISpecDirs = []string{"/etc/cdi", "/var/run/cdi"}

// containerdDefaultCapabilities is the capability set containerd gives a
// container with no adds (pkg/oci defaultUnixCaps); a rule lists only what is
// beyond it.
var containerdDefaultCapabilities = map[string]bool{
	"CAP_CHOWN": true, "CAP_DAC_OVERRIDE": true, "CAP_FSETID": true, "CAP_FOWNER": true,
	"CAP_MKNOD": true, "CAP_NET_RAW": true, "CAP_SETGID": true, "CAP_SETUID": true,
	"CAP_SETFCAP": true, "CAP_SETPCAP": true, "CAP_NET_BIND_SERVICE": true,
	"CAP_SYS_CHROOT": true, "CAP_KILL": true, "CAP_AUDIT_WRITE": true,
}

// observer turns NRI messages and OCI specs into allowlist.Observations. Its
// fields are the node facts no message carries.
type observer struct {
	// platformDir is the plugin's own socket directory as the runtime binds
	// it (workload_claims.socket_dir with /var/run mapped to /run): binds
	// from it are the platform's, not the operator's.
	platformDir string
	hostIP      string
	nodeName    string
	// cdiDeviceNodes resolves CDI device names to the device node paths
	// their specs inject, so those nodes are not reported as operator-added
	// devices. nil treats every device as unexplained.
	cdiDeviceNodes func(names []string) ([]string, error)
}

// observe builds the observation for one container from what the NRI
// message carries. digest is the resolved image digest. Capabilities,
// masked paths and no_new_privileges are not in the message; observeSpec
// adds them from the stored OCI spec.
func (o observer) observe(pod *api.PodSandbox, ctr *api.Container, digest string) allowlist.Observation {
	obs := allowlist.Observation{
		Digest:         digest,
		Argv:           ctr.GetArgs(),
		Env:            envMap(ctr.GetEnv()),
		Mounts:         map[string]allowlist.MountSource{},
		HostNamespaces: hostNamespaces(ctr.GetLinux().GetNamespaces()),
		Hooks:          hooksPresent(ctr.GetHooks()),
		Privileged:     sysfsWritable(nriMounts(ctr.GetMounts())),
		Sources:        o.sources(pod),
	}
	hostIPC := slices.Contains(obs.HostNamespaces, allowlist.HostNamespaceIPC)
	for _, m := range ctr.GetMounts() {
		if m.GetType() != "bind" {
			continue
		}
		src := runPath(m.GetSource())
		obs.Mounts[path.Clean(m.GetDestination())] = allowlist.MountSource{
			Path:  src,
			Class: o.classify(src, pod.GetUid(), ctr.GetPodSandboxId(), hostIPC),
		}
	}
	var devices []string
	for _, d := range ctr.GetLinux().GetDevices() {
		devices = append(devices, d.GetPath())
	}
	obs.Devices = o.unexplainedDevices(devices, ctr.GetCDIDevices())
	return obs
}

// observeSpec fills in what only the stored OCI spec carries. The mount
// list is re-read from the spec too, so the privileged inference is made
// from the same source as the capabilities.
func observeSpec(obs allowlist.Observation, spec *oci.Spec) allowlist.Observation {
	var mounts []mountView
	for _, m := range spec.Mounts {
		mounts = append(mounts, mountView{kind: m.Type, destination: m.Destination, options: m.Options})
	}
	obs.Privileged = sysfsWritable(mounts)
	obs.Capabilities = nil
	if spec.Process != nil && spec.Process.Capabilities != nil {
		for _, c := range spec.Process.Capabilities.Bounding {
			if !containerdDefaultCapabilities[c] {
				obs.Capabilities = append(obs.Capabilities, c)
			}
		}
		slices.Sort(obs.Capabilities)
	}
	// A privileged container has no masked paths by construction; its rule
	// says so through privileged, not unmaskedProc.
	obs.UnmaskedProc = !obs.Privileged && (spec.Linux == nil || len(spec.Linux.MaskedPaths) == 0)
	return obs
}

// specSecurity summarizes the spec fields no rule expresses yet, for the
// deny log a reviewer completes rules from.
func specSecurity(spec *oci.Spec) []any {
	seccomp := "unconfined"
	if spec.Linux != nil && spec.Linux.Seccomp != nil {
		seccomp = string(spec.Linux.Seccomp.DefaultAction)
	}
	noNewPrivs := spec.Process != nil && spec.Process.NoNewPrivileges
	return []any{"seccomp", seccomp, "no_new_privileges", noNewPrivs}
}

// sources are the pod-field values env From rules compare against.
func (o observer) sources(pod *api.PodSandbox) map[string]string {
	s := map[string]string{
		allowlist.FromPodName:      pod.GetName(),
		allowlist.FromPodNamespace: pod.GetNamespace(),
		allowlist.FromPodUID:       pod.GetUid(),
		allowlist.FromHostIP:       o.hostIP,
		allowlist.FromNodeName:     o.nodeName,
	}
	if ips := pod.GetIps(); len(ips) > 0 {
		s[allowlist.FromPodIP] = ips[0]
	}
	return s
}

// classify names the source class of a bind for Index.Admit: one of the
// reviewed classes when the kubelet or the platform put it there, the
// kubelet plugin name for a volume type the schema does not review, and
// hostPath for everything else. The plugin socket dir is platform; the
// measured image's state dir (policybundle.NodeStateDir: the policy dir and
// the attestation socket) is nodeState, a class of its own, so the platform
// rule every container carries for /etc/hosts cannot admit the socket bound
// there. hostIPC says the container shares the node's IPC namespace:
// containerd then binds the node's /dev/shm in place of the sandbox's, and
// render emits the same platform rule for both.
func (o observer) classify(source, podUID, sandboxID string, hostIPC bool) string {
	switch {
	case underDir(source, policybundle.NodeStateDir):
		return allowlist.SourceNodeState
	case underDir(source, o.platformDir):
		return allowlist.SourcePlatform
	case sandboxID != "" && strings.Contains(source, criSandboxDir+sandboxID+"/"):
		return allowlist.SourcePlatform
	case hostIPC && source == hostDevShm:
		return allowlist.SourcePlatform
	case strings.HasPrefix(source, localPathProvisionerRoot):
		return allowlist.SourcePVC
	}
	if podUID == "" {
		return allowlist.SourceHostPath
	}
	rest, ok := strings.CutPrefix(source, allowlist.KubeletVolumesRoot+podUID+"/")
	if !ok {
		return allowlist.SourceHostPath
	}
	switch {
	case rest == "etc-hosts", strings.HasPrefix(rest, "containers/"):
		return allowlist.SourcePlatform
	}
	volume, ok := strings.CutPrefix(rest, "volumes/")
	if !ok {
		return allowlist.SourceHostPath
	}
	plugin, name, _ := strings.Cut(volume, "/")
	switch plugin {
	case "kubernetes.io~empty-dir":
		return allowlist.SourceEmptyDir
	case "kubernetes.io~projected":
		if strings.HasPrefix(name, "kube-api-access-") {
			return allowlist.SourceServiceAccountToken
		}
		return "projected"
	case "kubernetes.io~csi", "kubernetes.io~local-volume":
		return allowlist.SourcePVC
	case "kubernetes.io~configmap":
		return "configMap"
	case "kubernetes.io~downward-api":
		return "downwardAPI"
	}
	return strings.TrimPrefix(plugin, "kubernetes.io~")
}

// unexplainedDevices drops the device nodes the container's CDI devices
// inject. A CDI lookup failure leaves every device unexplained: the rule
// then has to list them, which is the safe direction.
func (o observer) unexplainedDevices(devices []string, cdi []*api.CDIDevice) []string {
	if len(devices) == 0 {
		return nil
	}
	explained := map[string]bool{}
	if len(cdi) > 0 && o.cdiDeviceNodes != nil {
		names := make([]string, 0, len(cdi))
		for _, d := range cdi {
			names = append(names, d.GetName())
		}
		if nodes, err := o.cdiDeviceNodes(names); err == nil {
			for _, n := range nodes {
				explained[n] = true
			}
		}
	}
	var out []string
	for _, d := range devices {
		if !explained[d] {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// mountView is the part of a mount the privileged inference reads, shared
// between the NRI and OCI mount types.
type mountView struct {
	kind, destination string
	options           []string
}

func nriMounts(ms []*api.Mount) []mountView {
	out := make([]mountView, 0, len(ms))
	for _, m := range ms {
		out = append(out, mountView{kind: m.GetType(), destination: m.GetDestination(), options: m.GetOptions()})
	}
	return out
}

// sysfsWritable reports a writable /sys: containerd mounts sysfs read-only
// for every container and drops "ro" only through oci.WithPrivileged, so it
// is the privileged marker both the NRI message and the spec carry.
func sysfsWritable(mounts []mountView) bool {
	for _, m := range mounts {
		if m.kind == "sysfs" && m.destination == "/sys" && !slices.Contains(m.options, "ro") {
			return true
		}
	}
	return false
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, e := range env {
		name, value, _ := strings.Cut(e, "=")
		out[name] = value
	}
	return out
}

// hostNamespaces lists the namespaces the spec does not create: an absent
// entry means the container shares the node's.
func hostNamespaces(namespaces []*api.LinuxNamespace) []string {
	present := map[string]bool{}
	for _, ns := range namespaces {
		present[ns.GetType()] = true
	}
	var out []string
	for spec, rule := range map[string]string{"network": allowlist.HostNamespaceNet, "pid": allowlist.HostNamespacePID, "ipc": allowlist.HostNamespaceIPC} {
		if !present[spec] {
			out = append(out, rule)
		}
	}
	slices.Sort(out)
	return out
}

func hooksPresent(h *api.Hooks) bool {
	return len(h.GetPrestart())+len(h.GetCreateRuntime())+len(h.GetCreateContainer())+
		len(h.GetStartContainer())+len(h.GetPoststart())+len(h.GetPoststop()) > 0
}

func underDir(p, dir string) bool {
	return dir != "" && (p == dir || strings.HasPrefix(p, dir+"/"))
}

// runPath is a bind source as the runtime records it: cleaned, with /var/run
// mapped to /run as on the node image (the same mapping render applies to
// rule sources).
func runPath(p string) string {
	p = path.Clean(p)
	if p == "/var/run" || strings.HasPrefix(p, "/var/run/") {
		return "/run" + strings.TrimPrefix(p, "/var/run")
	}
	return p
}

// cdiSpec is the part of a CDI spec file the device explanation reads
// (tags.cncf.io/container-device-interface, spec v0.x): the kind and, per
// device, the device nodes its edits inject.
type cdiSpec struct {
	Kind           string          `yaml:"kind"`
	ContainerEdits cdiEdits        `yaml:"containerEdits"`
	Devices        []cdiSpecDevice `yaml:"devices"`
}

type cdiSpecDevice struct {
	Name           string   `yaml:"name"`
	ContainerEdits cdiEdits `yaml:"containerEdits"`
}

type cdiEdits struct {
	DeviceNodes []struct {
		Path string `yaml:"path"`
	} `yaml:"deviceNodes"`
}

// cdiDeviceNodesFrom returns a resolver over the spec files in dirs. Every
// spec file is read on each call; CDI specs change when a device plugin
// regenerates them and the plugin has no watcher.
func cdiDeviceNodesFrom(dirs []string) func(names []string) ([]string, error) {
	return func(names []string) ([]string, error) {
		specs, err := readCDISpecs(dirs)
		if err != nil {
			return nil, err
		}
		var nodes []string
		for _, name := range names {
			kind, device, ok := strings.Cut(name, "=")
			if !ok {
				return nil, fmt.Errorf("CDI device %q is not <kind>=<name>", name)
			}
			found := false
			for _, s := range specs {
				if s.Kind != kind {
					continue
				}
				for _, d := range s.Devices {
					if d.Name != device {
						continue
					}
					found = true
					for _, n := range s.ContainerEdits.DeviceNodes {
						nodes = append(nodes, n.Path)
					}
					for _, n := range d.ContainerEdits.DeviceNodes {
						nodes = append(nodes, n.Path)
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("CDI device %q is in no spec under %s", name, strings.Join(dirs, ", "))
			}
		}
		return nodes, nil
	}
}

func readCDISpecs(dirs []string) ([]cdiSpec, error) {
	var specs []cdiSpec
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read CDI specs: %w", err)
		}
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if !e.Type().IsRegular() || (ext != ".json" && ext != ".yaml" && ext != ".yml") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("read CDI spec: %w", err)
			}
			var s cdiSpec
			// YAML is a superset of JSON, so one decoder covers both file forms.
			if err := yaml.Unmarshal(b, &s); err != nil {
				return nil, fmt.Errorf("parse CDI spec %s: %w", e.Name(), err)
			}
			specs = append(specs, s)
		}
	}
	return specs, nil
}
