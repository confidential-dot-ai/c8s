package allowlist

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Observation is one container as a sealed enforcer sees it at create time.
// Every field is authoritative: unlike RunningContainer there is no
// "unobserved" state, because the sealed enforcer reads the whole OCI spec.
//
// Env maps name to value. Mounts maps each bind destination to its source.
// HostNamespaces lists the namespaces shared with the node (HostNamespace*).
// Capabilities lists capabilities beyond the runtime's default set, in OCI
// form. Hooks reports whether the spec carries any OCI hook. Sources carries
// the pod-field values env From rules resolve against, keyed by From*.
type Observation struct {
	Digest         string
	Argv           []string
	Env            map[string]string
	Mounts         map[string]MountSource
	HostNamespaces []string
	Devices        []string
	Capabilities   []string
	Hooks          bool
	Privileged     bool
	UnmaskedProc   bool
	Sources        map[string]string
}

// MountSource is where one bind destination's content comes from: the host
// path the runtime binds and the class the enforcer assigned it (Source*, or
// any other string for a source it could not classify).
type MountSource struct {
	Path  string
	Class string
}

// Admit reports whether a sealed document admits an observation and names
// the rule that did ("<entry>/<list>[<index>]"). There is no floor and no
// vacuity: the digest must be listed, and every observed field must satisfy
// the rule. Hooks are never admitted.
func (i *Index) Admit(obs Observation) (rule string, ok bool) {
	d, err := types.ParseDigest(obs.Digest)
	if err != nil || obs.Hooks {
		return "", false
	}
	for _, r := range i.rules[d.String()] {
		if r.container.admitsSealed(obs) {
			return r.name, true
		}
	}
	return "", false
}

func (c Container) admitsSealed(obs Observation) bool {
	rest, ok := c.Command.matchCommand(obs.Argv)
	if !ok || !c.Args.matchArgs(rest) {
		return false
	}
	if !c.Env.admitsValues(obs.Env, obs.Sources) || !c.Mounts.admitsSources(obs.Mounts, c.Privileges) {
		return false
	}
	p := c.Privileges
	if p == nil {
		p = &Privileges{}
	}
	if obs.Privileged && !p.Privileged {
		return false
	}
	if obs.UnmaskedProc && !p.UnmaskedProc {
		return false
	}
	if !subset(obs.HostNamespaces, p.HostNamespaces) {
		return false
	}
	// A privileged container holds every capability and every device; the
	// review string covers that, so the lists are not compared.
	return p.Privileged || (subset(obs.Devices, p.Devices) && subset(obs.Capabilities, p.Capabilities))
}

// admitsValues checks names as admits does, then each value against its
// rule: byte-exact for a literal, equal to the reported pod field for From.
func (p EnvPolicy) admitsValues(env, sources map[string]string) bool {
	if p.Policy != PolicyExact {
		return true
	}
	allowed := make(map[string]struct{}, len(p.Names))
	for _, n := range p.Names {
		allowed[n] = struct{}{}
	}
	for name, value := range env {
		if _, ok := allowed[name]; !ok {
			return false
		}
		rule, ok := p.Values[name]
		if !ok {
			continue
		}
		switch {
		case rule.Value != nil:
			if *rule.Value != value {
				return false
			}
		default:
			want, ok := sources[rule.From]
			if !ok || want != value {
				return false
			}
		}
	}
	return true
}

// admitsSources checks every observed bind against the destination list and
// its rule's class. A source outside the reviewed classes is admitted only
// through the entry's Privileges.HostPaths, whatever the mount policy says.
func (p MountPolicy) admitsSources(mounts map[string]MountSource, priv *Privileges) bool {
	allowed := make(map[string]struct{}, len(p.Destinations))
	for _, d := range p.Destinations {
		allowed[d] = struct{}{}
	}
	for dest, src := range mounts {
		if !reviewedClass(src.Class) && (priv == nil || !hostPathAdmitted(priv.HostPaths, src.Path)) {
			return false
		}
		if p.Policy != PolicyExact {
			continue
		}
		if _, ok := allowed[dest]; !ok {
			return false
		}
		rule, ok := p.Rules[dest]
		if !ok {
			continue
		}
		if rule.Source == SourceHostPath {
			if reviewedClass(src.Class) {
				return false
			}
			continue
		}
		if rule.Source != src.Class {
			return false
		}
	}
	return true
}

func reviewedClass(class string) bool {
	switch class {
	case SourceEmptyDir, SourceServiceAccountToken, SourcePVC, SourcePlatform:
		return true
	}
	return false
}

// hostPathAdmitted matches a bind source against the reviewed host paths: an
// entry without a trailing slash is the path itself, one with a trailing
// slash is a subtree. The source is cleaned first so ".." cannot escape a
// subtree; callers need not clean it.
func hostPathAdmitted(hostPaths []string, source string) bool {
	source = path.Clean(source)
	for _, h := range hostPaths {
		if h == source || (strings.HasSuffix(h, "/") && strings.HasPrefix(source, h)) {
			return true
		}
	}
	return false
}

func subset(observed, allowed []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for _, o := range observed {
		if _, ok := set[o]; !ok {
			return false
		}
	}
	return true
}

// LintSealed reports whether doc is a complete sealed document: the bytes a
// node measures, with a rule for everything a sealed enforcer observes. It
// is what the node plugin runs at boot and what `c8s allowlist lint --sealed`
// prints, so the two cannot disagree.
func LintSealed(doc []byte) error {
	findings, err := SealedFindings(doc)
	if err != nil {
		return err
	}
	if len(findings) > 0 {
		return fmt.Errorf("sealed allowlist: %s", strings.Join(findings, "; "))
	}
	return nil
}

// SealedFindings parses doc strictly and returns every way it falls short
// of a sealed document, one message each. A parse failure is the error.
func SealedFindings(doc []byte) ([]string, error) {
	al, err := ParseJSON(doc)
	if err != nil {
		return nil, err
	}
	canonical, err := al.Canonical()
	if err != nil {
		return nil, err
	}
	var out []string
	if !bytes.Equal(canonical, doc) {
		out = append(out, "document bytes are not its canonical form; the measured bytes must be what the reviewer read (rewrite it with `c8s allowlist export` and review again)")
	}
	return append(out, al.sealedFindings()...), nil
}

func (a *Allowlist) sealedFindings() []string {
	var out []string
	if len(a.Digests) > 0 {
		out = append(out, "digests must be empty: a sealed document admits nothing by digest alone")
	}
	names := make([]string, 0, len(a.Workloads))
	for name := range a.Workloads {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w := a.Workloads[name]
		for i, c := range w.InitContainers {
			out = append(out, c.sealedFindings(fmt.Sprintf("workload %q initContainers[%d] %s", name, i, c.Digest))...)
		}
		for i, c := range w.Containers {
			out = append(out, c.sealedFindings(fmt.Sprintf("workload %q containers[%d] %s", name, i, c.Digest))...)
		}
	}
	return out
}

func (c Container) sealedFindings(where string) []string {
	var out []string
	add := func(format string, args ...any) {
		out = append(out, where+": "+fmt.Sprintf(format, args...))
	}
	if c.Privileges != nil && c.Privileges.Review == "" {
		add("privileges.review is empty; say why this node-TCB entry is acceptable")
	}
	if c.Privileges == nil {
		if c.Command.Policy != PolicyExact {
			add("command must be exact for an unprivileged entry")
		}
		if c.Args.Policy == PolicyAny {
			add("args must be exact or deny for an unprivileged entry")
		}
		if c.Mounts.Policy != PolicyExact {
			add("mounts must be exact for an unprivileged entry")
		}
		if c.Env.Policy != PolicyExact {
			add("env must be exact for an unprivileged entry")
		}
	}
	if c.Env.Policy == PolicyExact && c.Env.Values == nil {
		add("env names carry no values; every name needs a value or from rule")
	}
	if c.Mounts.Policy == PolicyExact {
		if c.Mounts.Rules == nil {
			add("mount destinations carry no rules; every destination needs a source class")
		}
		for _, d := range c.Mounts.Destinations {
			r := c.Mounts.Rules[d]
			if r.Source == SourcePVC && r.Review == "" {
				add("mount %q is a pvc without a review; say why its contents cannot steer the workload", d)
			}
			if r.Source == SourceHostPath && c.Privileges == nil {
				add("mount %q is a hostPath on an unprivileged entry; list its host source under privileges.hostPaths", d)
			}
		}
	}
	return out
}
