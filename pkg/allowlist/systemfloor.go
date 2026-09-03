package allowlist

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/distribution/reference"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// SystemFloorSchema identifies the system-floor file the node image build
// emits next to its manifest.
const SystemFloorSchema = "c8s.system-floor/v1"

// SystemFloor lists the node image's system images (RKE2 static pods, CNI,
// DNS) with what the build can see of them: the image config. The build
// cannot see the argv, env and mounts the static pod manifests give them, so
// Env and Mounts start empty and Privileges.Review starts blank; the reviewer
// completes them from a dynamic node's observations before the document
// passes LintSealed.
type SystemFloor struct {
	Schema string             `json:"schema"`
	Images []SystemFloorImage `json:"images"`
}

// SystemFloorImage is one system image and its rule skeleton. Env keys and
// Mounts keys become the exact names and destinations of the rendered rule;
// both must be complete before the document seals, privileged or not. The
// skeleton carries an empty Privileges block; the reviewer completes it for
// a node-TCB image or sets it to null for an unprivileged one.
type SystemFloorImage struct {
	Ref        string               `json:"ref"`
	Digest     string               `json:"digest"`
	Entrypoint []string             `json:"entrypoint"`
	Cmd        []string             `json:"cmd"`
	Env        map[string]EnvValue  `json:"env"`
	Mounts     map[string]MountRule `json:"mounts"`
	Privileges *Privileges          `json:"privileges"`
}

// ParseSystemFloor decodes a system-floor file, rejecting unknown fields.
func ParseSystemFloor(data []byte) (*SystemFloor, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f SystemFloor
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode system floor: %w", err)
	}
	if f.Schema != SystemFloorSchema {
		return nil, fmt.Errorf("system floor: unknown schema %q (expected %q)", f.Schema, SystemFloorSchema)
	}
	return &f, nil
}

// Workloads renders one entry per image, named "system-<repo base>-<tag>".
// The argv rule pins the image config verbatim; a static pod that overrides
// it is the reviewer's edit.
func (f *SystemFloor) Workloads() (map[string]Workload, error) {
	out := make(map[string]Workload, len(f.Images))
	for _, img := range f.Images {
		name, err := systemEntryName(img.Ref)
		if err != nil {
			return nil, err
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("system floor: images %q and another share the entry name %q", img.Ref, name)
		}
		c, err := img.container()
		if err != nil {
			return nil, fmt.Errorf("system floor image %q: %w", img.Ref, err)
		}
		out[name] = Workload{Label: img.Ref, Containers: []Container{c}}
	}
	return out, nil
}

func (img SystemFloorImage) container() (Container, error) {
	digest, err := types.ParseDigest(img.Digest)
	if err != nil {
		return Container{}, err
	}
	named, err := reference.ParseDockerRef(img.Ref)
	if err != nil {
		return Container{}, fmt.Errorf("ref: %w", err)
	}
	c := Container{
		Digest:     digest,
		Image:      reference.TrimNamed(named).String() + "@" + digest.String(),
		Command:    ArgvRule(img.Entrypoint),
		Args:       ArgvRule(img.Cmd),
		Mounts:     MountRules(img.Mounts),
		Env:        EnvRules(img.Env),
		Privileges: img.Privileges,
	}
	if c.Command.Policy == PolicyDeny && c.Args.Policy == PolicyExact {
		// An image with only a Cmd runs it as its argv; the same shape a
		// pod template with args and no command produces.
		c.Command, c.Args = c.Args, ArgvPolicy{Policy: PolicyDeny}
	}
	return c, nil
}

// systemEntryName derives an entry name from an image reference:
// "system-<repository basename>-<tag>", squeezed to the entry grammar.
func systemEntryName(ref string) (string, error) {
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return "", fmt.Errorf("system floor image %q: %w", ref, err)
	}
	base := reference.Path(reference.TrimNamed(named))
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	name := "system-" + sanitizeEntryName(base)
	if tagged, ok := named.(reference.Tagged); ok {
		name += "-" + sanitizeEntryName(tagged.Tag())
	}
	if len(name) > MaxWorkloadNameLen {
		name = name[:MaxWorkloadNameLen]
	}
	return name, nil
}

func sanitizeEntryName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// ArgvRule pins an argv exactly, or denies it when there is nothing to pin.
func ArgvRule(argv []string) ArgvPolicy {
	if len(argv) == 0 {
		return ArgvPolicy{Policy: PolicyDeny}
	}
	return ArgvPolicy{Policy: PolicyExact, Argv: argv}
}

// EnvRules builds an exact env policy from name-keyed rules; an empty map is
// the unconstrained policy, which LintSealed refuses until the reviewer
// completes it.
func EnvRules(values map[string]EnvValue) EnvPolicy {
	if len(values) == 0 {
		return EnvPolicy{Policy: PolicyAny}
	}
	p := EnvPolicy{Policy: PolicyExact, Values: make(map[string]EnvValue, len(values))}
	for name, v := range values {
		p.Names = append(p.Names, name)
		p.Values[name] = v
	}
	return p
}

// MountRules builds an exact mount policy from destination-keyed rules; an
// empty map is the unconstrained policy, which LintSealed refuses until the
// reviewer completes it.
func MountRules(rules map[string]MountRule) MountPolicy {
	if len(rules) == 0 {
		return MountPolicy{Policy: PolicyAny}
	}
	p := MountPolicy{Policy: PolicyExact, Rules: make(map[string]MountRule, len(rules))}
	for dest, r := range rules {
		p.Destinations = append(p.Destinations, dest)
		p.Rules[dest] = r
	}
	return p
}
