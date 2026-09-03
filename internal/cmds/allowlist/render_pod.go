//go:build !c8s_node

package allowlist

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// platformMounts are the binds the kubelet and containerd add to every
// container's OCI spec besides the termination log.
var platformMounts = []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/shm"}

const serviceAccountMountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// fieldRefSources maps the kubelet fieldRef paths a rule can express to the
// From source whose value a sealed enforcer compares against.
var fieldRefSources = map[string]string{
	"metadata.name":      pkgallowlist.FromPodName,
	"metadata.namespace": pkgallowlist.FromPodNamespace,
	"metadata.uid":       pkgallowlist.FromPodUID,
	"status.podIP":       pkgallowlist.FromPodIP,
	"status.hostIP":      pkgallowlist.FromHostIP,
	"spec.nodeName":      pkgallowlist.FromNodeName,
}

// imageFacts is what the registry says about one image: its digest and the
// baked process defaults a pod template may override.
type imageFacts struct {
	label      string // repo@digest
	digest     types.Digest
	entrypoint []string
	cmd        []string
	env        []string
}

// imageResolver resolves image references through crane once each.
type imageResolver struct {
	ctx   context.Context
	cache map[string]*imageFacts
}

func (r *imageResolver) resolve(ref string) (*imageFacts, error) {
	if f, ok := r.cache[ref]; ok {
		return f, nil
	}
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return nil, fmt.Errorf("image %q: %w", ref, err)
	}
	repo := reference.TrimNamed(named).String()
	digest := ""
	if d, ok := named.(reference.Digested); ok {
		digest = d.Digest().String()
	} else if digest, err = crane.Digest(r.ctx, ref); err != nil {
		return nil, err
	}
	parsed, err := types.ParseDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("image %q: %w", ref, err)
	}
	label := repo + "@" + parsed.String()
	cfg, err := crane.Config(r.ctx, label)
	if err != nil {
		return nil, err
	}
	f := &imageFacts{label: label, digest: parsed, entrypoint: cfg.Config.Entrypoint, cmd: cfg.Config.Cmd, env: cfg.Config.Env}
	if r.cache == nil {
		r.cache = map[string]*imageFacts{}
	}
	r.cache[ref] = f
	return f, nil
}

// clusterFacts are the per-cluster constants every container rule depends
// on: the API server Service address the kubelet puts in the environment and
// the host directory the node serves its inventory and attestation sockets
// from, which the operator passes as --workload-claims-host-dir. Binds from
// that directory are platform mounts; it is empty until a chart is rendered.
type clusterFacts struct {
	serviceHost string
	servicePort string
	platformDir string
}

// platformSource reports whether a host path is the node's socket directory
// or lies under it.
func (c clusterFacts) platformSource(hostPath string) bool {
	return c.platformDir != "" && (hostPath == c.platformDir || strings.HasPrefix(hostPath, c.platformDir+"/"))
}

// hostPathAsBound is the source the runtime records for a hostPath volume:
// containerd cleans the path and resolves symlinks, and /var/run is a symlink
// to /run on the node image. A trailing slash in the spec must not become a
// subtree grant by accident, so the cleaned form is what the rule carries.
func hostPathAsBound(specPath string) string {
	p := path.Clean(specPath)
	if p == "/var/run" || strings.HasPrefix(p, "/var/run/") {
		return "/run" + strings.TrimPrefix(p, "/var/run")
	}
	return p
}

// serviceEnv is what the kubelet injects for the API server Service whatever
// enableServiceLinks says.
func (c clusterFacts) serviceEnv() map[string]string {
	addr := c.serviceHost + ":" + c.servicePort
	return map[string]string{
		"KUBERNETES_SERVICE_HOST":       c.serviceHost,
		"KUBERNETES_SERVICE_PORT":       c.servicePort,
		"KUBERNETES_SERVICE_PORT_HTTPS": c.servicePort,
		"KUBERNETES_PORT":               "tcp://" + addr,
		"KUBERNETES_PORT_443_TCP":       "tcp://" + addr,
		"KUBERNETES_PORT_443_TCP_PROTO": "tcp",
		"KUBERNETES_PORT_443_TCP_PORT":  c.servicePort,
		"KUBERNETES_PORT_443_TCP_ADDR":  c.serviceHost,
	}
}

// podRules derives one rule per container of a pod, init containers first.
func podRules(pod *corev1.Pod, images *imageResolver, cluster clusterFacts, rep *report) (init, main []pkgallowlist.Container, err error) {
	where := pod.Namespace + "/" + pod.Name
	if pod.Spec.EnableServiceLinks == nil || *pod.Spec.EnableServiceLinks {
		rep.warnf("pod %s: enableServiceLinks is not false; the kubelet adds env vars for every Service in the namespace, which no exact rule can list", where)
	}
	for i := range pod.Spec.InitContainers {
		c, err := containerRule(pod, &pod.Spec.InitContainers[i], images, cluster, rep)
		if err != nil {
			return nil, nil, fmt.Errorf("pod %s initContainers[%d] %q: %w", where, i, pod.Spec.InitContainers[i].Name, err)
		}
		init = append(init, c)
	}
	for i := range pod.Spec.Containers {
		c, err := containerRule(pod, &pod.Spec.Containers[i], images, cluster, rep)
		if err != nil {
			return nil, nil, fmt.Errorf("pod %s containers[%d] %q: %w", where, i, pod.Spec.Containers[i].Name, err)
		}
		main = append(main, c)
	}
	return init, main, nil
}

func containerRule(pod *corev1.Pod, c *corev1.Container, images *imageResolver, cluster clusterFacts, rep *report) (pkgallowlist.Container, error) {
	img, err := images.resolve(c.Image)
	if err != nil {
		return pkgallowlist.Container{}, err
	}
	env, kubeletEnv, err := envRules(pod, c, img, cluster)
	if err != nil {
		return pkgallowlist.Container{}, err
	}
	priv := privilegesOf(pod, c)
	mounts, err := mountRules(pod, c, priv, cluster, rep)
	if err != nil {
		return pkgallowlist.Container{}, err
	}
	if len(priv.HostPaths) == 0 && !priv.Privileged && !priv.UnmaskedProc &&
		len(priv.HostNamespaces) == 0 && len(priv.Capabilities) == 0 {
		priv = nil
	}
	command, args, err := argvRules(c, img, kubeletEnv, priv != nil)
	if err != nil {
		return pkgallowlist.Container{}, err
	}
	return pkgallowlist.Container{
		Digest:     img.digest,
		Image:      img.label,
		Command:    command,
		Args:       args,
		Mounts:     pkgallowlist.MountRules(mounts),
		Env:        pkgallowlist.EnvRules(env),
		Privileges: priv,
	}, nil
}

// kubeletEnv is what the kubelet expands $(VAR) references against: the API
// server Service variables and the template's own env. Image config Env and
// the HOSTNAME the runtime sets are not in it, so references to them stay
// verbatim in the running container. dynamic holds the fieldRef names, whose
// value the kubelet knows only per pod.
type kubeletEnv struct {
	literals map[string]string
	dynamic  map[string]bool
}

// envRules reproduces the container's environment as the kubelet and
// containerd assemble it: image config Env, HOSTNAME, the API server Service
// variables, then the template's own env, which overrides by name. It also
// returns the kubelet's expansion environment for argvRules.
func envRules(pod *corev1.Pod, c *corev1.Container, img *imageFacts, cluster clusterFacts) (map[string]pkgallowlist.EnvValue, kubeletEnv, error) {
	if len(c.EnvFrom) != 0 {
		return nil, kubeletEnv{}, fmt.Errorf("envFrom pulls names from a ConfigMap or Secret the operator controls; no exact rule can list them")
	}
	rules := map[string]pkgallowlist.EnvValue{}
	literal := func(name, value string) { rules[name] = pkgallowlist.EnvValue{Value: &value} }
	for _, kv := range img.env {
		name, value, _ := strings.Cut(kv, "=")
		literal(name, value)
	}
	switch {
	case pod.Spec.Hostname != "":
		literal("HOSTNAME", pod.Spec.Hostname)
	case pod.Spec.HostNetwork:
		rules["HOSTNAME"] = pkgallowlist.EnvValue{From: pkgallowlist.FromNodeName}
	default:
		rules["HOSTNAME"] = pkgallowlist.EnvValue{From: pkgallowlist.FromPodName}
	}
	env := kubeletEnv{literals: cluster.serviceEnv(), dynamic: map[string]bool{}}
	for name, value := range env.literals {
		literal(name, value)
	}
	// A value sees only the entries declared before it; argv sees them all.
	for _, e := range c.Env {
		switch {
		case e.ValueFrom == nil:
			value, dynamic := expandEnv(e.Value, env)
			if dynamic != "" {
				return nil, kubeletEnv{}, fmt.Errorf("env %s references $(%s), whose value varies per pod; no exact rule can pin the result", e.Name, dynamic)
			}
			literal(e.Name, value)
			env.literals[e.Name] = value
			delete(env.dynamic, e.Name)
		case e.ValueFrom.FieldRef != nil:
			from, ok := fieldRefSources[e.ValueFrom.FieldRef.FieldPath]
			if !ok {
				return nil, kubeletEnv{}, fmt.Errorf("env %s: fieldRef %q has no from source (want one of metadata.name, metadata.namespace, metadata.uid, status.podIP, status.hostIP, spec.nodeName)", e.Name, e.ValueFrom.FieldRef.FieldPath)
			}
			rules[e.Name] = pkgallowlist.EnvValue{From: from}
			env.dynamic[e.Name] = true
			delete(env.literals, e.Name)
		default:
			return nil, kubeletEnv{}, fmt.Errorf("env %s takes its value from a ConfigMap, Secret or resource field the operator controls; no exact rule can pin it", e.Name)
		}
	}
	return rules, env, nil
}

var envRefRE = regexp.MustCompile(`\$\$?\([A-Za-z_][A-Za-z0-9_]*\)`)

// expandEnv applies the kubelet's $(VAR) expansion: a known literal is
// substituted, $$(VAR) is the escape for a literal $(VAR), an unknown name
// stays verbatim. A reference to a per-pod name makes the result dynamic,
// and that name is returned.
func expandEnv(s string, env kubeletEnv) (string, string) {
	dynamic := ""
	out := envRefRE.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "$$") {
			return m[1:]
		}
		name := m[2 : len(m)-1]
		if v, ok := env.literals[name]; ok {
			return v
		}
		if env.dynamic[name] {
			dynamic = name
		}
		return m
	})
	return out, dynamic
}

// argvRules pins the effective argv with Kubernetes semantics: command
// overrides the image Entrypoint, args overrides Cmd, and a command without
// args drops the image Cmd. A privileged entry whose argv expands a per-pod
// variable gets an unconstrained segment; an unprivileged one is an error.
func argvRules(c *corev1.Container, img *imageFacts, env kubeletEnv, privileged bool) (command, args pkgallowlist.ArgvPolicy, err error) {
	// expand substitutes literals; a per-pod reference leaves the segment
	// unconstrained for a privileged entry and is an error otherwise.
	expand := func(tokens []string, what string) (out []string, unconstrained bool, err error) {
		for _, t := range tokens {
			v, dynamic := expandEnv(t, env)
			if dynamic == "" {
				out = append(out, v)
				continue
			}
			if !privileged {
				return nil, false, fmt.Errorf("%s expands $(%s), whose value varies per pod; no exact rule can pin it", what, dynamic)
			}
			return nil, true, nil
		}
		return out, false, nil
	}
	cmdPart, argPart := img.entrypoint, img.cmd
	switch {
	case len(c.Command) > 0:
		cmdPart, argPart = c.Command, nil
		if len(c.Args) > 0 {
			argPart = c.Args
		}
	case len(c.Args) > 0:
		argPart = c.Args
	}
	cmdPart, cmdAny, err := expand(cmdPart, "command")
	if err != nil {
		return command, args, err
	}
	argPart, argAny, err := expand(argPart, "args")
	if err != nil {
		return command, args, err
	}
	if len(cmdPart) == 0 && len(argPart) == 0 && !cmdAny && !argAny {
		return command, args, fmt.Errorf("no argv: the image has no Entrypoint or Cmd and the template sets neither command nor args")
	}
	if len(cmdPart) == 0 && !cmdAny {
		// An image with only a Cmd runs it as the whole argv.
		cmdPart, cmdAny, argPart, argAny = argPart, argAny, nil, false
	}
	command, args = pkgallowlist.ArgvRule(cmdPart), pkgallowlist.ArgvRule(argPart)
	unconstrained := pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
	switch {
	case cmdAny:
		// An unconstrained command consumes the whole argv, so nothing is
		// left for an args rule to anchor on.
		command, args = unconstrained, unconstrained
	case argAny:
		args = unconstrained
	}
	return command, args, nil
}

// privilegesOf reads the pod and container security settings into a
// Privileges skeleton with an empty review. HostPaths is filled by
// mountRules. A container with nothing beyond the ordinary is unprivileged
// (the caller drops the empty skeleton).
func privilegesOf(pod *corev1.Pod, c *corev1.Container) *pkgallowlist.Privileges {
	p := &pkgallowlist.Privileges{}
	if pod.Spec.HostNetwork {
		p.HostNamespaces = append(p.HostNamespaces, pkgallowlist.HostNamespaceNet)
	}
	if pod.Spec.HostPID {
		p.HostNamespaces = append(p.HostNamespaces, pkgallowlist.HostNamespacePID)
	}
	if pod.Spec.HostIPC {
		p.HostNamespaces = append(p.HostNamespaces, pkgallowlist.HostNamespaceIPC)
	}
	if sc := c.SecurityContext; sc != nil {
		if sc.Privileged != nil && *sc.Privileged {
			p.Privileged = true
		}
		if sc.ProcMount != nil && *sc.ProcMount == corev1.UnmaskedProcMount {
			p.UnmaskedProc = true
		}
		if sc.Capabilities != nil {
			for _, cap := range sc.Capabilities.Add {
				p.Capabilities = append(p.Capabilities, "CAP_"+strings.ToUpper(string(cap)))
			}
		}
	}
	return p
}

// mountRules classifies every bind the container will carry: the template's
// volumeMounts by their volume source, plus what the kubelet adds. A source
// the node supplies goes under privileges.hostPaths, recorded as the runtime
// binds it.
func mountRules(pod *corev1.Pod, c *corev1.Container, priv *pkgallowlist.Privileges, cluster clusterFacts, rep *report) (map[string]pkgallowlist.MountRule, error) {
	volumes := make(map[string]corev1.Volume, len(pod.Spec.Volumes))
	for _, v := range pod.Spec.Volumes {
		volumes[v.Name] = v
	}
	rules := map[string]pkgallowlist.MountRule{}
	hostPath := func(dest, source string) {
		rules[dest] = pkgallowlist.MountRule{Source: pkgallowlist.SourceHostPath}
		priv.HostPaths = append(priv.HostPaths, source)
	}
	for _, vm := range c.VolumeMounts {
		v, ok := volumes[vm.Name]
		if !ok {
			return nil, fmt.Errorf("volumeMount %q names no volume", vm.Name)
		}
		dest := path.Clean(vm.MountPath)
		switch {
		case v.EmptyDir != nil:
			rules[dest] = pkgallowlist.MountRule{Source: pkgallowlist.SourceEmptyDir}
		case v.PersistentVolumeClaim != nil, v.Ephemeral != nil:
			// The review stays empty here; the sealed findings in the report
			// ask for it.
			rules[dest] = pkgallowlist.MountRule{Source: pkgallowlist.SourcePVC}
		case v.HostPath != nil:
			source := hostPathAsBound(v.HostPath.Path)
			if source != v.HostPath.Path {
				rep.notef("pod %s/%s container %s: hostPath %q is bound as %q", pod.Namespace, pod.Name, c.Name, v.HostPath.Path, source)
			}
			if cluster.platformSource(source) {
				rules[dest] = pkgallowlist.MountRule{Source: pkgallowlist.SourcePlatform}
				continue
			}
			hostPath(dest, source)
		case v.ConfigMap != nil, v.Secret != nil, v.Projected != nil, v.DownwardAPI != nil, v.CSI != nil:
			hostPath(dest, pkgallowlist.KubeletVolumesRoot)
		default:
			return nil, fmt.Errorf("volume %q has a source type this tool cannot classify", vm.Name)
		}
	}
	for _, dest := range platformMounts {
		if _, taken := rules[dest]; !taken {
			rules[dest] = pkgallowlist.MountRule{Source: pkgallowlist.SourcePlatform}
		}
	}
	termination := c.TerminationMessagePath
	if termination == "" {
		termination = corev1.TerminationMessagePathDefault
	}
	if _, taken := rules[termination]; !taken {
		rules[termination] = pkgallowlist.MountRule{Source: pkgallowlist.SourcePlatform}
	}
	automount := pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken
	if _, taken := rules[serviceAccountMountPath]; automount && !taken {
		rules[serviceAccountMountPath] = pkgallowlist.MountRule{Source: pkgallowlist.SourceServiceAccountToken}
	}
	sort.Strings(priv.HostPaths)
	return rules, nil
}
