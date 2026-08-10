package allowlist

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

func containerWith(t *testing.T, mounts MountPolicy, env EnvPolicy) Container {
	t.Helper()
	c := Container{
		Digest:  mustDigest(t, "sha256:"+strings.Repeat("a", 64)),
		Command: ArgvPolicy{Policy: PolicyAny},
		Args:    ArgvPolicy{Policy: PolicyAny},
		Mounts:  mounts,
		Env:     env,
	}
	// normalizeContainers mutates the slice it is given, so read the result back
	// out of it rather than off the copy that went in.
	cs := []Container{c}
	if err := normalizeContainers("w", "containers", cs); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return cs[0]
}

func running(digest string, mounts, env []string) RunningContainer {
	return RunningContainer{Digest: digest, BindMounts: mounts, EnvNames: env}
}

// The threat this policy exists for: the host stages bytes in the sandbox
// seeding directory (a legitimate CopyFile destination) and binds them over a
// path inside an allowlisted image, so the container runs host code while every
// digest still reports as admitted.
func TestMountPolicyRefusesAnUndeclaredDestination(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts", "/var/run/secrets/kubernetes.io/serviceaccount"}},
		EnvPolicy{Policy: PolicyAny})

	if !c.admits(running(digest, []string{"/etc/hosts"}, nil)) {
		t.Error("a declared destination was refused")
	}
	if c.admits(running(digest, []string{"/etc/hosts", "/usr/local/bin/get-cert"}, nil)) {
		t.Error("a bind over an image path was admitted")
	}
}

// An absent policy has to mean "unconstrained": every container carries a mount
// table it never declared, so a Deny default would refuse every real pod.
func TestAbsentMountAndEnvPolicyAreUnconstrained(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t, MountPolicy{}, EnvPolicy{})

	if c.Mounts.Policy != PolicyAny || c.Env.Policy != PolicyAny {
		t.Fatalf("normalized to %q/%q, want %q", c.Mounts.Policy, c.Env.Policy, PolicyAny)
	}
	if !c.admits(running(digest, []string{"/anything", "/at/all"}, []string{"LD_PRELOAD"})) {
		t.Error("an absent policy refused a container")
	}
}

// LD_PRELOAD is the sharp case: an injected name is code execution inside an
// otherwise-allowlisted image.
func TestEnvPolicyRefusesAnUndeclaredName(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t, MountPolicy{Policy: PolicyAny},
		EnvPolicy{Policy: PolicyExact, Names: []string{"PATH", "HOME"}})

	if !c.admits(running(digest, nil, []string{"PATH", "HOME"})) {
		t.Error("declared names were refused")
	}
	if c.admits(running(digest, nil, []string{"PATH", "LD_PRELOAD"})) {
		t.Error("an injected environment name was admitted")
	}
}

// An enforcer that cannot see a field leaves it nil. That is not a violation —
// the host-side NRI plugin gates images on a node CVM and never sees a guest's
// mount table, and refusing there would deny every pod it checks.
func TestUnobservedFieldsAreNotViolations(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts"}},
		EnvPolicy{Policy: PolicyExact, Names: []string{"PATH"}})

	if !c.admits(RunningContainer{Digest: digest}) {
		t.Error("an enforcer that observes neither field was refused")
	}
}

func TestMountAndEnvPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Container
	}{
		{"exact mounts with no destinations", Container{Mounts: MountPolicy{Policy: PolicyExact}}},
		{"any mounts carrying destinations", Container{Mounts: MountPolicy{Policy: PolicyAny, Destinations: []string{"/x"}}}},
		{"relative destination", Container{Mounts: MountPolicy{Policy: PolicyExact, Destinations: []string{"etc/hosts"}}}},
		{"unknown mount policy", Container{Mounts: MountPolicy{Policy: "sometimes"}}},
		{"exact env with no names", Container{Env: EnvPolicy{Policy: PolicyExact}}},
		{"any env carrying names", Container{Env: EnvPolicy{Policy: PolicyAny, Names: []string{"PATH"}}}},
		{"name containing =", Container{Env: EnvPolicy{Policy: PolicyExact, Names: []string{"PATH=/bin"}}}},
		{"unknown env policy", Container{Env: EnvPolicy{Policy: "sometimes"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			c.Digest = mustDigest(t, "sha256:"+strings.Repeat("a", 64))
			if err := normalizeContainers("w", "containers", []Container{c}); err == nil {
				t.Error("normalize accepted an invalid policy")
			}
		})
	}
}

// Canonical is compared byte-for-byte across pulls, so the lists have to be a
// function of content rather than of the order an operator wrote them.
func TestMountAndEnvListsAreOrderIndependent(t *testing.T) {
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/b", "/a", "/b"}},
		EnvPolicy{Policy: PolicyExact, Names: []string{"B", "A", "B"}})

	if got := strings.Join(c.Mounts.Destinations, ","); got != "/a,/b" {
		t.Errorf("destinations = %q, want sorted and deduplicated", got)
	}
	if got := strings.Join(c.Env.Names, ","); got != "A,B" {
		t.Errorf("names = %q, want sorted and deduplicated", got)
	}
}

// A document from a newer release must not freeze an older consumer's policy.
func TestServedParseIgnoresUnknownFields(t *testing.T) {
	doc := `{"schema":"` + Schema + `","digests":{},"workloads":{},"somethingNewer":{"x":1}}`
	if _, err := ParseServedJSON([]byte(doc)); err != nil {
		t.Fatalf("ParseServedJSON rejected an unknown field: %v", err)
	}
	if _, err := ParseJSON([]byte(doc)); err == nil {
		t.Error("ParseJSON accepted an unknown field in an operator-authored document")
	}
}
