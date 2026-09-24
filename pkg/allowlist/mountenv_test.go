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
	observed, _ := ObserveEnv(env)
	classified := make([]ObservedMount, len(mounts))
	for i, destination := range mounts {
		classified[i] = ObservedMount{Destination: destination, Class: MountEmptyDir, Storage: MountMemory}
	}
	return RunningContainer{Digest: digest, Mounts: classified, Env: observed}
}

func emptyDirRules(destinations ...string) []MountRule {
	rules := make([]MountRule, len(destinations))
	for i, destination := range destinations {
		rules[i] = MountRule{Destination: destination, Kind: MountEmptyDir}
	}
	return rules
}

// The threat this policy exists for: the host stages bytes in the sandbox
// seeding directory (a legitimate CopyFile destination) and binds them over a
// path inside an allowlisted image, so the container runs host code while every
// digest still reports as admitted.
func TestMountPolicyRefusesAnUndeclaredDestination(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/etc/hosts")},
		EnvPolicy{Policy: PolicyAny})

	if !c.admits(running(digest, []string{"/etc/hosts"}, nil)) {
		t.Error("a declared destination was refused")
	}
	if c.admits(running(digest, []string{"/etc/hosts", "/usr/local/bin/get-cert"}, nil)) {
		t.Error("a bind over an image path was admitted")
	}
}

func TestAbsentMountPolicyAllowsOnlyPlatformMounts(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t, MountPolicy{}, EnvPolicy{})

	if c.Mounts.Policy != PolicyDeny || c.Env.Policy != PolicyAny {
		t.Fatalf("normalized to mounts=%q env=%q, want deny/any", c.Mounts.Policy, c.Env.Policy)
	}
	if c.admits(running(digest, []string{"/anything"}, []string{"LD_PRELOAD"})) {
		t.Error("an absent mount policy admitted a workload mount")
	}
}

func TestContainerIsUnconstrained(t *testing.T) {
	base := Container{
		Command: ArgvPolicy{Policy: PolicyAny},
		Args:    ArgvPolicy{Policy: PolicyAny},
	}
	tests := []struct {
		name string
		edit func(*Container)
		want bool
	}{
		{name: "absent mount policy is deny"},
		{name: "explicit any", edit: func(c *Container) {
			c.Mounts.Policy = PolicyAny
			c.Env.Policy = PolicyAny
		}, want: true},
		{name: "pinned command", edit: func(c *Container) {
			c.Command = ArgvPolicy{Policy: PolicyExact, Argv: []string{"/app"}}
		}},
		{name: "pinned args", edit: func(c *Container) {
			c.Args = ArgvPolicy{Policy: PolicyDeny}
		}},
		{name: "pinned mounts", edit: func(c *Container) {
			c.Mounts = MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/data")}
		}},
		{name: "pinned env", edit: func(c *Container) {
			c.Env = EnvPolicy{Policy: PolicyDeny}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			if tt.edit != nil {
				tt.edit(&c)
			}
			if got := c.IsUnconstrained(); got != tt.want {
				t.Fatalf("IsUnconstrained() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainerConstraintsNormalizeEveryPolicy(t *testing.T) {
	c := Container{Digest: mustDigest(t, "sha256:"+strings.Repeat("a", 64))}
	cs := []Container{c}
	if err := normalizeContainers("w", "containers", cs); err != nil {
		t.Fatal(err)
	}
	c = cs[0]
	if c.Command.Policy != PolicyDeny || c.Args.Policy != PolicyDeny ||
		c.Mounts.Policy != PolicyDeny || c.Env.Policy != PolicyAny {
		t.Fatalf("normalized policies = command %q, args %q, mounts %q, env %q",
			c.Command.Policy, c.Args.Policy, c.Mounts.Policy, c.Env.Policy)
	}
}

func TestContainerConstraintsAllParticipateInAdmission(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/data")},
		EnvPolicy{Policy: PolicyExact, Values: map[string]string{"MODE": "prod"}})
	c.Command = ArgvPolicy{Policy: PolicyExact, Argv: []string{"/app"}}
	c.Args = ArgvPolicy{Policy: PolicyExact, Argv: []string{"serve"}}

	valid := running(digest, []string{"/data"}, []string{"MODE=prod"})
	valid.Argv = []string{"/app", "serve"}
	if !c.admits(valid) {
		t.Fatal("all matching constraints were refused")
	}

	tests := []struct {
		name string
		edit func(*RunningContainer)
	}{
		{name: "command", edit: func(r *RunningContainer) { r.Argv[0] = "/bin/sh" }},
		{name: "args", edit: func(r *RunningContainer) { r.Argv[1] = "debug" }},
		{name: "mounts", edit: func(r *RunningContainer) {
			r.Mounts = []ObservedMount{{Destination: "/host", Class: MountHost, Storage: MountUnknown}}
		}},
		{name: "env", edit: func(r *RunningContainer) {
			r.Env, _ = ObserveEnv([]string{"MODE=dev"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid
			r.Argv = append([]string(nil), valid.Argv...)
			tt.edit(&r)
			if c.admits(r) {
				t.Errorf("container admitted with mismatched %s constraint", tt.name)
			}
		})
	}
}

// LD_PRELOAD is the sharp case: an injected name is code execution inside an
// otherwise-allowlisted image.
func TestEnvPolicyRefusesAnUndeclaredName(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t, MountPolicy{Policy: PolicyAny},
		EnvPolicy{Policy: PolicyExact, Values: map[string]string{"PATH": "/bin", "HOME": "/"}})

	if !c.admits(running(digest, nil, []string{"PATH=/bin", "HOME=/"})) {
		t.Error("declared names were refused")
	}
	if c.admits(running(digest, nil, []string{"PATH=/bin", "HOME=/", "LD_PRELOAD=/evil.so"})) {
		t.Error("an injected environment name was admitted")
	}
}

func TestUnobservedMountsCannotSatisfyExact(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/etc/hosts")},
		EnvPolicy{Policy: PolicyAny})

	if c.admits(RunningContainer{Digest: digest}) {
		t.Error("unavailable mount evidence satisfied exact policy")
	}
}

func TestMountAndEnvPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Container
	}{
		{"exact mounts with no rules", Container{Mounts: MountPolicy{Policy: PolicyExact}}},
		{"any mounts carrying rules", Container{Mounts: MountPolicy{Policy: PolicyAny, Rules: emptyDirRules("/x")}}},
		{"relative destination", Container{Mounts: MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("etc/hosts")}}},
		{"duplicate destination", Container{Mounts: MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/x", "/x")}}},
		{"platform rule", Container{Mounts: MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/x", Kind: MountPlatform}}}}},
		{"data outside prefix", Container{Mounts: MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/config", Kind: MountData}}}}},
		{"unknown mount policy", Container{Mounts: MountPolicy{Policy: "sometimes"}}},
		{"exact env with no values", Container{Env: EnvPolicy{Policy: PolicyExact}}},
		{"any env carrying values", Container{Env: EnvPolicy{Policy: PolicyAny, Values: map[string]string{"PATH": "/bin"}}}},
		{"name containing =", Container{Env: EnvPolicy{Policy: PolicyExact, Values: map[string]string{"PATH=/bin": ""}}}},
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
func TestMountRulesAreOrderIndependent(t *testing.T) {
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/b", "/a")},
		EnvPolicy{Policy: PolicyAny})

	if got := c.Mounts.Rules; got[0].Destination != "/a" || got[1].Destination != "/b" {
		t.Errorf("rules = %#v, want destination order /a,/b", got)
	}
}

func TestTypedMountPolicy(t *testing.T) {
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{
		{Destination: "/cache", Kind: MountEmptyDir},
		{Destination: "/mnt/c8s-data/config", Kind: MountData},
	}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mounts []ObservedMount
		want   bool
	}{
		{"memory emptyDir and encrypted data", []ObservedMount{
			{Destination: "/cache", Class: MountEmptyDir, Storage: MountMemory},
			{Destination: "/mnt/c8s-data/config", Class: MountData, Storage: MountEncrypted},
		}, true},
		{"platform baseline ignored", []ObservedMount{
			{Destination: "/etc/hosts", Class: MountPlatform, Storage: MountUnknown},
			{Destination: "/cache", Class: MountEmptyDir, Storage: MountEncrypted},
			{Destination: "/mnt/c8s-data/config", Class: MountData, Storage: MountMemory},
		}, true},
		{"plain emptyDir", []ObservedMount{
			{Destination: "/cache", Class: MountEmptyDir, Storage: MountUnknown},
			{Destination: "/mnt/c8s-data/config", Class: MountData, Storage: MountEncrypted},
		}, false},
		{"wrong kind", []ObservedMount{
			{Destination: "/cache", Class: MountData, Storage: MountMemory},
			{Destination: "/mnt/c8s-data/config", Class: MountData, Storage: MountEncrypted},
		}, false},
		{"missing rule", []ObservedMount{{Destination: "/cache", Class: MountEmptyDir, Storage: MountMemory}}, false},
		{"duplicate destination", []ObservedMount{
			{Destination: "/cache", Class: MountEmptyDir, Storage: MountMemory},
			{Destination: "/cache", Class: MountEmptyDir, Storage: MountMemory},
			{Destination: "/mnt/c8s-data/config", Class: MountData, Storage: MountEncrypted},
		}, false},
		{"host mount", []ObservedMount{
			{Destination: "/cache", Class: MountEmptyDir, Storage: MountMemory},
			{Destination: "/mnt/c8s-data/config", Class: MountData, Storage: MountEncrypted},
			{Destination: "/host", Class: MountHost, Storage: MountUnknown},
		}, false},
		{"unavailable", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policy.admits(tt.mounts); got != tt.want {
				t.Fatalf("admits = %v, want %v", got, tt.want)
			}
		})
	}
}

// A document from a newer release must not freeze an older consumer's policy.
func TestServedParseIgnoresUnknownFields(t *testing.T) {
	doc := `{"schema":"` + Schema + `","workloads":{},"somethingNewer":{"x":1}}`
	if _, err := ParseServedJSON([]byte(doc)); err != nil {
		t.Fatalf("ParseServedJSON rejected an unknown field: %v", err)
	}
	if _, err := ParseJSON([]byte(doc)); err == nil {
		t.Error("ParseJSON accepted an unknown field in an operator-authored document")
	}
}
