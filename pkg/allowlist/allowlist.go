// Package allowlist defines the CDS-served image allowlist and its deterministic
// canonical serialization.
//
// The allowlist has two layers. Digests is the floor: a digest -> image-label
// map whose images are admitted by digest alone. The measured pod-CVM guest
// seed and explicit compatibility entries can live here. Node-CVM has a
// separate local cold-boot floor that is not part of this active document.
// Workloads carries policy:
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
	"io"
	"log/slog"
	"path"
	"slices"
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

// Container roles are part of the complete-set release decision. They are not
// used for per-container admission, where a container starts before the whole
// Pod can exist.
const (
	ContainerRoleInit = "init"
	ContainerRoleMain = "main"
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
	Label string `json:"label,omitempty"`
	// Identity is the stable logical mesh identity. Different exact entries
	// can share it during a bounded rollout. Empty means the entry name.
	Identity       string         `json:"identity,omitempty"`
	InitContainers []Container    `json:"initContainers"`
	Containers     []Container    `json:"containers"`
	Secrets        *SecretsPolicy `json:"secrets,omitempty"`
}

// Container binds a digest to the process policy permitted for it.
type Container struct {
	// Name is the Kubernetes container name. Old entries can omit it, but a
	// generated exact entry always sets it. The complete-set matcher uses it to
	// keep two equal process policies and the init/main lists distinct.
	Name    string       `json:"name,omitempty"`
	Digest  types.Digest `json:"digest"`
	Image   string       `json:"image,omitempty"`
	Command ArgvPolicy   `json:"command"`
	Args    ArgvPolicy   `json:"args"`
	Mounts  MountPolicy  `json:"mounts,omitempty"`
	Env     EnvPolicy    `json:"env,omitempty"`
}

// ArgvPolicy governs part of a container's effective argv (the OCI process.args
// a pod actually runs), mirroring the Kubernetes command/args split: Command is
// matched as an exact prefix of the argv, and Args governs the remainder after
// it. Exact requires equality, Any leaves it unconstrained, Deny requires it to
// be empty. An absent policy defaults to Deny.
type ArgvPolicy struct {
	Policy      string           `json:"policy"`
	Argv        []string         `json:"argv,omitempty"`
	EnvBindings []ArgvEnvBinding `json:"env_bindings,omitempty"`
}

// ArgvEnvBinding binds one exact argv item to public downward-API values that
// kubelet expands before CRI admission. Index is relative to this policy.
type ArgvEnvBinding struct {
	Index int      `json:"index"`
	Names []string `json:"names"`
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
type MountPolicy struct {
	Policy       string   `json:"policy"`
	Destinations []string `json:"destinations,omitempty"`
	// Kinds pins storage provenance at a confidentiality-critical destination.
	// New generated entries use private or node. private is TEE-private memory.
	// node is persistent or host-selected. pod and legacy Kubernetes kind values
	// remain accepted for migration and map to the same matching classes.
	Kinds map[string]string `json:"kinds,omitempty"`
}

// EnvPolicy governs the environment variable NAMES a container may run with.
// Values are not matched: they carry secrets, and an allowlist is served to
// every enforcer. Exact requires every name to appear in Names; Any, the
// default, leaves them unconstrained.
type EnvPolicy struct {
	Policy string   `json:"policy"`
	Names  []string `json:"names,omitempty"`
	// Prefixes admits runtime-created name families without guessing the full
	// set. Generated Kubernetes system policy uses KUBERNETES_ while
	// enableServiceLinks=false. It still rejects LD_PRELOAD and every unrelated
	// injected name.
	Prefixes []string `json:"prefixes,omitempty"`
}

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
	if err := requireJSONEOF(dec); err != nil {
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
	if err := requireJSONEOF(dec); err != nil {
		return nil, fmt.Errorf("decode workload: %w", err)
	}
	if w.Identity != "" && !ValidWorkloadName(w.Identity) {
		return nil, fmt.Errorf("entry identity %q must be at most %d bytes and match [A-Za-z0-9][A-Za-z0-9._-]*", w.Identity, MaxWorkloadNameLen)
	}
	if err := normalizeContainers("entry", "initContainers", w.InitContainers); err != nil {
		return nil, err
	}
	if err := normalizeContainers("entry", "containers", w.Containers); err != nil {
		return nil, err
	}
	if err := validateContainerNames("entry", w); err != nil {
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
		if w.Identity != "" && !ValidWorkloadName(w.Identity) {
			return fmt.Errorf("workload %q identity %q must be at most %d bytes and match [A-Za-z0-9][A-Za-z0-9._-]*", name, w.Identity, MaxWorkloadNameLen)
		}
		if err := normalizeContainers(name, "initContainers", w.InitContainers); err != nil {
			return err
		}
		if err := normalizeContainers(name, "containers", w.Containers); err != nil {
			return err
		}
		if err := validateContainerNames(name, w); err != nil {
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

// WorkloadIdentity returns the stable logical identity of an exact policy
// entry. Empty retains the historical entry-name identity.
func WorkloadIdentity(entryName string, workload Workload) string {
	if workload.Identity != "" {
		return workload.Identity
	}
	return entryName
}

func normalizeContainers(workload, field string, cs []Container) error {
	for i := range cs {
		c := &cs[i]
		if c.Name != "" && !validContainerName(c.Name) {
			return fmt.Errorf("workload %q %s[%d]: container name %q must be a lowercase DNS label", workload, field, i, c.Name)
		}
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
	}
	return nil
}

func validateContainerNames(workload string, w Workload) error {
	seen := map[string]string{}
	for _, part := range []struct {
		role string
		cs   []Container
	}{{ContainerRoleInit, w.InitContainers}, {ContainerRoleMain, w.Containers}} {
		for _, c := range part.cs {
			if c.Name == "" {
				continue
			}
			if prior, ok := seen[c.Name]; ok {
				return fmt.Errorf("workload %q container name %q is declared more than once (%s and %s)", workload, c.Name, prior, part.role)
			}
			seen[c.Name] = part.role
		}
	}
	for _, init := range w.InitContainers {
		if init.Name != "" {
			continue
		}
		for _, main := range w.Containers {
			if main.Name == "" && init.Digest == main.Digest && policyKey(init) == policyKey(main) {
				return fmt.Errorf("workload %q has the same unnamed container policy in init and main roles; re-derive it with container names before migration", workload)
			}
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
		if len(p.Destinations) != 0 || len(p.Kinds) != 0 {
			return fmt.Errorf("any policy takes no destinations or kinds")
		}
		p.Policy = PolicyAny
		p.Destinations = nil
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
		allowedKinds := map[string]struct{}{
			"private": {}, "pod": {}, "node": {}, "unknown": {},
			// Accepted for existing v1 documents. The matcher converts them to
			// private/pod/node requirements.
			"empty-dir": {}, "configmap": {}, "secret": {}, "projected": {},
			"downward-api": {}, "host-path": {},
		}
		for destination, kind := range p.Kinds {
			if !path.IsAbs(destination) {
				return fmt.Errorf("kind destination %q is not an absolute path", destination)
			}
			if _, ok := allowedKinds[kind]; !ok {
				return fmt.Errorf("unsupported mount kind %q at %s", kind, destination)
			}
			if !slices.Contains(p.Destinations, destination) {
				return fmt.Errorf("mount kind destination %q is not in destinations", destination)
			}
		}
	default:
		return fmt.Errorf("unknown mount policy %q (want any or exact)", p.Policy)
	}
	return nil
}

// normalizeEnv validates an env policy, canonicalizing an absent policy to Any
// for the same reason as mounts: a container inherits names it did not declare.
func normalizeEnv(p *EnvPolicy) error {
	switch p.Policy {
	case PolicyAny, "":
		if len(p.Names) != 0 || len(p.Prefixes) != 0 {
			return fmt.Errorf("any policy takes no names or prefixes")
		}
		p.Policy = PolicyAny
		p.Names = nil
		p.Prefixes = nil
	case PolicyExact:
		for _, n := range p.Names {
			if n == "" || strings.ContainsRune(n, '=') {
				return fmt.Errorf("environment name %q is empty or contains '='", n)
			}
		}
		p.Names = sortedUnique(p.Names)
		for _, prefix := range p.Prefixes {
			if prefix == "" || strings.ContainsRune(prefix, '=') {
				return fmt.Errorf("environment prefix %q is empty or contains '='", prefix)
			}
		}
		p.Prefixes = sortedUnique(p.Prefixes)
	default:
		return fmt.Errorf("unknown env policy %q (want any or exact)", p.Policy)
	}
	return nil
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
		if len(p.Argv) != 0 || len(p.EnvBindings) != 0 {
			return fmt.Errorf("%s policy takes no argv or environment bindings", p.Policy)
		}
		p.Argv = nil
		p.EnvBindings = nil
	case PolicyExact:
		if len(p.Argv) == 0 {
			return fmt.Errorf("exact policy requires a non-empty argv")
		}
		seenIndex := map[int]struct{}{}
		for i := range p.EnvBindings {
			binding := &p.EnvBindings[i]
			if binding.Index < 0 || binding.Index >= len(p.Argv) {
				return fmt.Errorf("environment binding index %d is outside argv", binding.Index)
			}
			if _, exists := seenIndex[binding.Index]; exists {
				return fmt.Errorf("environment binding index %d is declared more than once", binding.Index)
			}
			seenIndex[binding.Index] = struct{}{}
			binding.Names = sortedUnique(binding.Names)
			if len(binding.Names) == 0 {
				return fmt.Errorf("environment binding index %d has no names", binding.Index)
			}
			for _, name := range binding.Names {
				if name != "HOST_IP" && name != "NODE_IP" {
					return fmt.Errorf("environment binding name %q is not a supported public downward-API value", name)
				}
				if !strings.Contains(p.Argv[binding.Index], "$("+name+")") {
					return fmt.Errorf("environment binding index %d does not contain $(%s)", binding.Index, name)
				}
			}
		}
		sort.Slice(p.EnvBindings, func(i, j int) bool { return p.EnvBindings[i].Index < p.EnvBindings[j].Index })
	case "":
		p.Policy = PolicyDeny
		p.Argv = nil
		p.EnvBindings = nil
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
		if cs[i].Name != cs[j].Name {
			return cs[i].Name < cs[j].Name
		}
		di, dj := cs[i].Digest.String(), cs[j].Digest.String()
		if di != dj {
			return di < dj
		}
		return policyKey(cs[i]) < policyKey(cs[j])
	})
}

func policyKey(c Container) string {
	b, _ := json.Marshal([]any{c.Name, c.Command, c.Args, c.Mounts, c.Env})
	return string(b)
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	err := dec.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("more than one JSON value")
	}
	return fmt.Errorf("trailing data: %w", err)
}

func validContainerName(name string) bool {
	if name == "" || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
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
