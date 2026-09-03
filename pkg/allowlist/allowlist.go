// Package allowlist defines the CDS-served image allowlist and its deterministic
// canonical serialization.
//
// The allowlist has two layers. Digests is the floor: a digest -> image-label
// map whose images are admitted by digest alone. The measured guest seed and
// standalone/injected component images live here. Workloads carries policy:
// each named entry pins an init/main container set, every container carries
// entrypoint/cmd (argv) policy, and the entry as a whole carries a secret-store
// grant. Policy is always looked up by container digest — the entry name and
// image labels are informational, never a trust-bearing key, because the image
// reference a pod presents is chosen by the untrusted host while the digest is
// bound to the bytes that run.
//
// Canonical is Go's json.Marshal of the normalized struct: fixed field order,
// map keys sorted by encoding/json, container and path lists sorted by
// normalize. Workers compare it byte-for-byte across pulls, so any
// nondeterminism would show up as spurious churn — normalize exists to remove
// it.
package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Schema identifies the allowlist document format. It is the first field of the
// canonical form.
const Schema = "c8s.allowlist/v1"

// Policy values. Argv policies use Deny/Any/Exact; secrets grants use
// Deny/Allow — never Any (normalizeSecrets).
const (
	PolicyDeny  = "deny"
	PolicyAny   = "any"
	PolicyExact = "exact"
	PolicyAllow = "allow"
)

// Allowlist is the complete image allowlist.
type Allowlist struct {
	Schema    string              `json:"schema"`
	Digests   map[string]string   `json:"digests"`
	Workloads map[string]Workload `json:"workloads"`
}

// Workload is a named policy entry. Label is an informational image reference.
// Secrets is nil when the entry grants nothing, which is what a "deny" grant
// normalizes to: an entry that releases nothing carries no "secrets" key at
// all, so a consumer that does not know the field never sees it.
type Workload struct {
	Label          string         `json:"label,omitempty"`
	InitContainers []Container    `json:"initContainers"`
	Containers     []Container    `json:"containers"`
	Secrets        *SecretsPolicy `json:"secrets,omitempty"`
}

// Container binds a digest to the process policy permitted for it.
//
// Privileges is nil for an ordinary workload container. A pointer so a
// document written before the field existed canonicalizes to the same bytes.
type Container struct {
	Digest     types.Digest `json:"digest"`
	Image      string       `json:"image,omitempty"`
	Command    ArgvPolicy   `json:"command"`
	Args       ArgvPolicy   `json:"args"`
	Mounts     MountPolicy  `json:"mounts,omitempty"`
	Env        EnvPolicy    `json:"env,omitempty"`
	Privileges *Privileges  `json:"privileges,omitempty"`
}

// Privileges declares what a node-TCB container may hold beyond an ordinary
// workload: host namespaces, extra capabilities, devices, host bind sources,
// an unmasked /proc, or full privilege. A sealed document requires Review to
// say why the entry is acceptable; the reviewer, not the tool, is the
// authority on a privileged pod.
//
// Capabilities lists capabilities beyond the runtime's default set, in OCI
// form (CAP_NET_ADMIN); Privileged implies all of them and every device, so
// those lists are not matched for a privileged entry. HostPaths lists host bind sources admitted for
// classes outside the reviewed mount classes (hostPath, configMap, secret,
// projected); an entry ending in "/" admits the subtree, and the kubelet's
// own volumes live under KubeletVolumesRoot.
type Privileges struct {
	Privileged     bool     `json:"privileged,omitempty"`
	HostNamespaces []string `json:"hostNamespaces,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
	Devices        []string `json:"devices,omitempty"`
	HostPaths      []string `json:"hostPaths,omitempty"`
	UnmaskedProc   bool     `json:"unmaskedProc,omitempty"`
	Review         string   `json:"review"`
}

// Host namespaces a Privileges entry may share with the node.
const (
	HostNamespaceNet = "net"
	HostNamespacePID = "pid"
	HostNamespaceIPC = "ipc"
)

// KubeletVolumesRoot is where the kubelet materializes configMap, secret and
// projected volumes (<root><pod uid>/volumes/kubernetes.io~<plugin>/<name>).
// A Privileges.HostPaths entry naming it admits every such volume.
const KubeletVolumesRoot = "/var/lib/kubelet/pods/"

// ArgvPolicy governs part of a container's effective argv (the OCI process.args
// a pod actually runs), mirroring the Kubernetes command/args split: Command is
// matched as an exact prefix of the argv, and Args governs the remainder after
// it. Exact requires equality, Any leaves it unconstrained, Deny requires it to
// be empty. An absent policy defaults to Deny.
type ArgvPolicy struct {
	Policy string   `json:"policy"`
	Argv   []string `json:"argv,omitempty"`
}

// MountPolicy governs where the host may bind content into the container.
//
// It constrains BIND mounts only — a mount whose source is an absolute guest
// path. The rest of a container's mount table names filesystem types (proc,
// sysfs, tmpfs, devpts, mqueue, cgroup) and carries nothing in, so pinning it
// would make an operator restate the OCI base set to say nothing.
//
// Exact requires every bind destination to appear in Destinations, which is the
// set an operator recognises: it is what the pod spec's volumeMounts declare,
// plus the handful the kubelet always adds (/etc/hosts, /etc/hostname,
// /etc/resolv.conf, /dev/termination-log, /dev/shm, the serviceaccount token).
// Any leaves them unconstrained, and is what an absent policy means — unlike
// argv, a Deny default would refuse every real pod, since the base set is never
// empty.
//
// Rules, keyed by destination, classify what may be bound there. A sealed
// document (Index.Admit) requires one per destination; dynamic enforcers
// ignore them. When present the key set must equal Destinations.
type MountPolicy struct {
	Policy       string               `json:"policy"`
	Destinations []string             `json:"destinations,omitempty"`
	Rules        map[string]MountRule `json:"rules,omitempty"`
}

// MountRule is the reviewed source class of one bind destination. Review is
// required for a pvc source: it names why operator-supplied contents at that
// path cannot steer the workload.
type MountRule struct {
	Source string `json:"source"`
	Review string `json:"review,omitempty"`
}

// Mount source classes. The first four are what a pod spec and the kubelet
// put there; SourceHostPath marks a destination whose content the node
// supplies (hostPath, configMap, secret, projected) and is admitted only
// through Privileges.HostPaths.
const (
	SourceEmptyDir            = "emptyDir"
	SourceServiceAccountToken = "serviceAccountToken"
	SourcePVC                 = "pvc"
	SourcePlatform            = "platform"
	SourceHostPath            = "hostPath"
)

// EnvPolicy governs the environment variable NAMES a container may run with,
// and, in a sealed document, their values.
//
// Dynamic enforcers match names only: values carry secrets there, and the
// allowlist is served to every enforcer. A sealed document is reviewed and
// measured, not secret, so Values pins each name to a literal or to a pod
// field (Index.Admit). When present the key set must equal Names.
type EnvPolicy struct {
	Policy string              `json:"policy"`
	Names  []string            `json:"names,omitempty"`
	Values map[string]EnvValue `json:"values,omitempty"`
}

// EnvValue pins one environment variable: Value matches byte-exact, From
// matches the pod field the enforcer reports under that name. Exactly one is
// set.
type EnvValue struct {
	Value *string `json:"value,omitempty"`
	From  string  `json:"from,omitempty"`
}

// From sources an EnvValue may name. They are what the kubelet's fieldRef
// injects and what the NRI PodSandbox (or the node) can report.
const (
	FromPodIP        = "podIP"
	FromPodName      = "podName"
	FromPodNamespace = "podNamespace"
	FromPodUID       = "podUID"
	FromHostIP       = "hostIP"
	FromNodeName     = "nodeName"
)

// SecretsPolicy grants secret-store read/write globs to a whole workload entry.
// The subject is the entry, not a container: the value is delivered on a volume
// every container in the pod can read, so a per-container grant would not
// describe what is actually released. See docs/secrets.md.
type SecretsPolicy struct {
	Policy string   `json:"policy"`
	Read   []string `json:"read,omitempty"`
	Write  []string `json:"write,omitempty"`
}

// ParseJSON decodes and validates an operator-authored allowlist, rejecting
// unknown fields so a typo or a foreign document fails loud instead of parsing
// as empty. The result is normalized (digests lowercased and deduplicated,
// container and path lists sorted) so Canonical is a function of content alone.
//
// Use ParseServedJSON for a document pulled from CDS.
func ParseJSON(data []byte) (*Allowlist, error) {
	return parseJSON(data, true)
}

// ParseServedJSON decodes a document served by CDS, ignoring fields it does not
// know. Its consumers pin a schema version in a launch measurement, so a strict
// parse would make any newer field freeze their policy until a node-image
// rebuild. See docs/secrets.md — "Upgrading".
func ParseServedJSON(data []byte) (*Allowlist, error) {
	return parseJSON(data, false)
}

func parseJSON(data []byte, strict bool) (*Allowlist, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	var a Allowlist
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("decode allowlist: %w", err)
	}
	if err := a.normalize(strict); err != nil {
		return nil, err
	}
	return &a, nil
}

// ParseWorkloadJSON decodes and validates a single workload entry — the body of
// a PUT /allowlist/workloads/{name} — applying the same normalization as
// ParseJSON so a stored entry is canonical.
func ParseWorkloadJSON(data []byte) (*Workload, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w Workload
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("decode workload: %w", err)
	}
	if err := normalizeContainers("entry", "initContainers", w.InitContainers); err != nil {
		return nil, err
	}
	if err := normalizeContainers("entry", "containers", w.Containers); err != nil {
		return nil, err
	}
	if err := normalizeSecrets(&w.Secrets); err != nil {
		return nil, fmt.Errorf("entry secrets: %w", err)
	}
	sortContainers(w.InitContainers)
	sortContainers(w.Containers)
	return &w, nil
}

// Digests returns every container digest in the workload (init and main), for
// building a digest index.
func (w Workload) Digests() []types.Digest {
	out := make([]types.Digest, 0, len(w.InitContainers)+len(w.Containers))
	for _, c := range w.InitContainers {
		out = append(out, c.Digest)
	}
	for _, c := range w.Containers {
		out = append(out, c.Digest)
	}
	return out
}

// Canonical returns the canonical byte serialization: json.Marshal of the
// normalized struct.
func (a *Allowlist) Canonical() ([]byte, error) {
	return json.Marshal(a)
}

// CanonicalDigest returns SHA-256 over Canonical() — the policy digest clients
// pin and the matched-workload stamp carries (docs/ratls.md).
func (a *Allowlist) CanonicalDigest() ([]byte, error) {
	canonical, err := a.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// normalize canonicalizes the document. strict is the write/ingest posture
// (ParseJSON): it enforces MaxWorkloadNameLen, so no entry that the cw selector
// or the leaf stamp cannot represent ever enters the store. A served document
// (ParseServedJSON) is not ours to reject over that bound — it arrived after
// entries could already have been written, and failing the whole document would
// break every allowlist pull in the cluster over one legacy name — so an
// over-long entry is dropped instead. See docs/allowlist-and-capabilities.md.
func (a *Allowlist) normalize(strict bool) error {
	if a.Schema != Schema {
		return fmt.Errorf("allowlist: unknown schema %q (expected %q)", a.Schema, Schema)
	}
	if a.Digests != nil {
		canon := make(map[string]string, len(a.Digests))
		for d, img := range a.Digests {
			pd, err := types.ParseDigest(d)
			if err != nil {
				return fmt.Errorf("floor digest %q: %w", d, err)
			}
			if _, dup := canon[pd.String()]; dup {
				return fmt.Errorf("duplicate floor digest %s", pd.String())
			}
			canon[pd.String()] = img
		}
		a.Digests = canon
	}
	for name, w := range a.Workloads {
		// The grammar is not negotiable on either path: the name is used
		// verbatim as a URL path segment.
		if !workloadNameGrammarOK(name) {
			return fmt.Errorf("workload name %q must match [A-Za-z0-9][A-Za-z0-9._-]* (it is a URL path segment)", name)
		}
		if len(name) > MaxWorkloadNameLen {
			if strict {
				return fmt.Errorf("workload name %q is %d bytes; the maximum is %d (it is mirrored as a Kubernetes label value)", name, len(name), MaxWorkloadNameLen)
			}
			// Dropping is fail-closed: the entry's digests stop being admitted
			// by this consumer. It could never have been named on a leaf either
			// (ratls.MatchedWorkload.Validate applies the same bound), so
			// nothing that depended on it is lost.
			slog.Warn("allowlist: dropping a served workload entry whose name exceeds the label-value bound",
				"name", name, "bytes", len(name), "max", MaxWorkloadNameLen)
			delete(a.Workloads, name)
			continue
		}
		if err := normalizeContainers(name, "initContainers", w.InitContainers); err != nil {
			return err
		}
		if err := normalizeContainers(name, "containers", w.Containers); err != nil {
			return err
		}
		if err := normalizeSecrets(&w.Secrets); err != nil {
			return fmt.Errorf("workload %q secrets: %w", name, err)
		}
		sortContainers(w.InitContainers)
		sortContainers(w.Containers)
		a.Workloads[name] = w
	}
	return nil
}

func normalizeContainers(workload, field string, cs []Container) error {
	for i := range cs {
		c := &cs[i]
		if c.Digest.String() == "" {
			return fmt.Errorf("workload %q %s[%d]: digest is required", workload, field, i)
		}
		if err := normalizeArgv(&c.Command); err != nil {
			return fmt.Errorf("workload %q %s %s command: %w", workload, field, c.Digest, err)
		}
		if err := normalizeArgv(&c.Args); err != nil {
			return fmt.Errorf("workload %q %s %s args: %w", workload, field, c.Digest, err)
		}
		if err := normalizeMounts(&c.Mounts); err != nil {
			return fmt.Errorf("workload %q %s %s mounts: %w", workload, field, c.Digest, err)
		}
		if err := normalizeEnv(&c.Env); err != nil {
			return fmt.Errorf("workload %q %s %s env: %w", workload, field, c.Digest, err)
		}
		if err := normalizePrivileges(c.Privileges); err != nil {
			return fmt.Errorf("workload %q %s %s privileges: %w", workload, field, c.Digest, err)
		}
	}
	return nil
}

// normalizeMounts validates a mount policy. An absent policy canonicalizes to
// Any: every container has a mount table it did not ask for (the OCI base set,
// /etc/hosts, the serviceaccount token), so Deny would refuse every real pod and
// an operator adopting this field would be opting into an outage.
func normalizeMounts(p *MountPolicy) error {
	switch p.Policy {
	case PolicyAny, "":
		if len(p.Destinations) != 0 {
			return fmt.Errorf("any policy takes no destinations")
		}
		if len(p.Rules) != 0 {
			return fmt.Errorf("any policy takes no rules")
		}
		p.Policy = PolicyAny
		p.Destinations = nil
		p.Rules = nil
	case PolicyExact:
		if len(p.Destinations) == 0 {
			return fmt.Errorf("exact policy requires at least one destination")
		}
		for _, d := range p.Destinations {
			if !path.IsAbs(d) {
				return fmt.Errorf("destination %q is not an absolute path", d)
			}
		}
		p.Destinations = sortedUnique(p.Destinations)
		if len(p.Rules) == 0 {
			p.Rules = nil
			break
		}
		if err := requireSameKeys(p.Rules, p.Destinations, "rule", "destination"); err != nil {
			return err
		}
		for d, r := range p.Rules {
			switch r.Source {
			case SourceEmptyDir, SourceServiceAccountToken, SourcePVC, SourcePlatform, SourceHostPath:
			default:
				return fmt.Errorf("rule %q: unknown source %q (want %s, %s, %s, %s or %s)", d, r.Source,
					SourceEmptyDir, SourceServiceAccountToken, SourcePVC, SourcePlatform, SourceHostPath)
			}
		}
	default:
		return fmt.Errorf("unknown mount policy %q (want any or exact)", p.Policy)
	}
	return nil
}

// requireSameKeys checks that a rule map covers exactly the listed names:
// a name without a rule is a gap the reviewer never saw, and a rule for an
// unlisted name is a typo that would otherwise pin nothing.
func requireSameKeys[V any](rules map[string]V, names []string, ruleWord, nameWord string) error {
	listed := make(map[string]struct{}, len(names))
	for _, n := range names {
		listed[n] = struct{}{}
	}
	for k := range rules {
		if _, ok := listed[k]; !ok {
			return fmt.Errorf("%s for %q names no listed %s", ruleWord, k, nameWord)
		}
	}
	for _, n := range names {
		if _, ok := rules[n]; !ok {
			return fmt.Errorf("%s %q has no %s", nameWord, n, ruleWord)
		}
	}
	return nil
}

// normalizeEnv validates an env policy, canonicalizing an absent policy to Any
// for the same reason as mounts: a container inherits names it did not declare.
func normalizeEnv(p *EnvPolicy) error {
	switch p.Policy {
	case PolicyAny, "":
		if len(p.Names) != 0 {
			return fmt.Errorf("any policy takes no names")
		}
		if len(p.Values) != 0 {
			return fmt.Errorf("any policy takes no values")
		}
		p.Policy = PolicyAny
		p.Names = nil
		p.Values = nil
	case PolicyExact:
		if len(p.Names) == 0 {
			return fmt.Errorf("exact policy requires at least one name")
		}
		for _, n := range p.Names {
			if n == "" || strings.ContainsRune(n, '=') {
				return fmt.Errorf("environment name %q is empty or contains '='", n)
			}
		}
		p.Names = sortedUnique(p.Names)
		if len(p.Values) == 0 {
			p.Values = nil
			break
		}
		if err := requireSameKeys(p.Values, p.Names, "value", "name"); err != nil {
			return err
		}
		for n, v := range p.Values {
			if err := v.validate(); err != nil {
				return fmt.Errorf("value for %q: %w", n, err)
			}
		}
	default:
		return fmt.Errorf("unknown env policy %q (want any or exact)", p.Policy)
	}
	return nil
}

func (v EnvValue) validate() error {
	switch {
	case v.Value != nil && v.From != "":
		return fmt.Errorf("value and from are mutually exclusive")
	case v.Value == nil && v.From == "":
		return fmt.Errorf("one of value or from is required")
	case v.From != "" && !validFromSource(v.From):
		return fmt.Errorf("unknown from source %q (want %s, %s, %s, %s, %s or %s)", v.From,
			FromPodIP, FromPodName, FromPodNamespace, FromPodUID, FromHostIP, FromNodeName)
	}
	return nil
}

func validFromSource(from string) bool {
	switch from {
	case FromPodIP, FromPodName, FromPodNamespace, FromPodUID, FromHostIP, FromNodeName:
		return true
	}
	return false
}

// normalizePrivileges validates a privileges block in place. A nil block is
// the ordinary, unprivileged container. An empty non-nil block is kept: its
// presence is the reviewer's declaration that the entry is node TCB, and the
// sealed lint then insists on the review text.
func normalizePrivileges(p *Privileges) error {
	if p == nil {
		return nil
	}
	for _, ns := range p.HostNamespaces {
		switch ns {
		case HostNamespaceNet, HostNamespacePID, HostNamespaceIPC:
		default:
			return fmt.Errorf("unknown host namespace %q (want %s, %s or %s)", ns, HostNamespaceNet, HostNamespacePID, HostNamespaceIPC)
		}
	}
	for _, c := range p.Capabilities {
		if !strings.HasPrefix(c, "CAP_") || strings.ToUpper(c) != c {
			return fmt.Errorf("capability %q is not in OCI form (CAP_NAME)", c)
		}
	}
	for _, d := range p.Devices {
		if !path.IsAbs(d) {
			return fmt.Errorf("device %q is not an absolute path", d)
		}
	}
	for _, h := range p.HostPaths {
		if !path.IsAbs(h) {
			return fmt.Errorf("host path %q is not an absolute path", h)
		}
	}
	p.HostNamespaces = emptyToNil(sortedUnique(p.HostNamespaces))
	p.Capabilities = emptyToNil(sortedUnique(p.Capabilities))
	p.Devices = emptyToNil(sortedUnique(p.Devices))
	p.HostPaths = emptyToNil(sortedUnique(p.HostPaths))
	return nil
}

func emptyToNil(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return in
}

// sortedUnique makes a list a function of its content, so Canonical does not
// churn on the order an operator happened to write.
func sortedUnique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// normalizeArgv validates an argv policy and canonicalizes an absent policy to
// Deny, so a minimally-specified container is maximally restrictive.
func normalizeArgv(p *ArgvPolicy) error {
	switch p.Policy {
	case PolicyDeny, PolicyAny:
		if len(p.Argv) != 0 {
			return fmt.Errorf("%s policy takes no argv", p.Policy)
		}
		p.Argv = nil
	case PolicyExact:
		if len(p.Argv) == 0 {
			return fmt.Errorf("exact policy requires a non-empty argv")
		}
	case "":
		p.Policy = PolicyDeny
		p.Argv = nil
	default:
		return fmt.Errorf("unknown argv policy %q (want deny, any, or exact)", p.Policy)
	}
	return nil
}

// normalizeSecrets validates an entry's secrets grant, canonicalizing "grants
// nothing" to a nil grant so it does not appear on the wire at all.
//
// Unlike argv policy there is no "any": an unbounded secret grant is never what
// an operator means, and the same three characters that are inert today would
// otherwise become "every secret in the cluster".
func normalizeSecrets(pp **SecretsPolicy) error {
	p := *pp
	if p == nil {
		return nil
	}
	switch p.Policy {
	case PolicyDeny, "":
		if len(p.Read) != 0 || len(p.Write) != 0 {
			return fmt.Errorf("deny policy grants no paths")
		}
		*pp = nil
	case PolicyAllow:
		read, err := normalizeGlobs(p.Read)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		write, err := normalizeGlobs(p.Write)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if len(read) == 0 {
			// The only client creates with POST and then re-reads: a write-only
			// grant leaves every replica that loses the create race permanently
			// without the value.
			return fmt.Errorf("allow policy requires at least one read path")
		}
		p.Read, p.Write = read, write
	default:
		return fmt.Errorf("unknown secrets policy %q (want deny or allow)", p.Policy)
	}
	return nil
}

// normalizeGlobs validates that every path is absolute and clean, dedupes, and
// sorts. A trailing "/**" (subtree match) is the only wildcard form permitted.
func normalizeGlobs(globs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(globs))
	out := make([]string, 0, len(globs))
	for _, g := range globs {
		if !strings.HasPrefix(g, "/") {
			return nil, fmt.Errorf("path %q must be absolute", g)
		}
		base := strings.TrimSuffix(g, "/**")
		if base == "" {
			base = "/"
		}
		if strings.Contains(base, "*") {
			return nil, fmt.Errorf("path %q: the only wildcard is a trailing /**", g)
		}
		if path.Clean(base) != base {
			return nil, fmt.Errorf("path %q is not clean (no . or ..)", g)
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// sortContainers orders a container list by digest, then by a stable rendering
// of its policy, so a set is serialized identically regardless of input order.
// Duplicate digests are permitted: one image may run under several argv policies
// (e.g. a shared base image invoked differently by different workloads).
func sortContainers(cs []Container) {
	sort.SliceStable(cs, func(i, j int) bool {
		di, dj := cs[i].Digest.String(), cs[j].Digest.String()
		if di != dj {
			return di < dj
		}
		return policyKey(cs[i]) < policyKey(cs[j])
	})
}

// policyKey renders every policy field; Image is informational and stays out.
func policyKey(c Container) string {
	b, _ := json.Marshal([]any{c.Command, c.Args, c.Mounts, c.Env, c.Privileges})
	return string(b)
}

// MaxWorkloadNameLen bounds an entry name to the Kubernetes label-value length,
// so the confidential.ai/cw selector, an allowlist entry name, and the
// matched-workload leaf stamp (pkg/ratls) can all represent it. It is enforced
// where entries are written, not where a served document is read — see
// normalize.
const MaxWorkloadNameLen = 63

// workloadNameGrammarOK restricts entry names to a URL-safe segment so a name
// can be used verbatim as a path parameter without escaping ambiguity. It does
// not apply MaxWorkloadNameLen; ValidWorkloadName is the bounded form.
func workloadNameGrammarOK(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case (b == '.' || b == '_' || b == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// ValidWorkloadName reports whether name is a legal workload entry name: the
// URL-path-segment grammar, bounded to MaxWorkloadNameLen. It is the check the
// write path, the admission selector, and the matched-workload certificate
// stamp share.
//
// It is not identical to what every consumer accepts: a name may end in '.',
// '_' or '-' here and still fail k8s validation.IsValidLabelValue, which the
// injection webhook applies to the cw label. Tightening the grammar to close
// that gap would retroactively invalidate stored entries, so the narrower rule
// stays where it is enforced.
func ValidWorkloadName(name string) bool {
	return workloadNameGrammarOK(name) && len(name) <= MaxWorkloadNameLen
}
