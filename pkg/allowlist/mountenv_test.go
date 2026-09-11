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
	return RunningContainer{Digest: digest, BindMounts: mounts, Env: observed}
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
		EnvPolicy{Policy: PolicyExact, Values: map[string]string{"PATH": "/bin", "HOME": "/"}})

	if !c.admits(running(digest, nil, []string{"PATH=/bin", "HOME=/"})) {
		t.Error("declared names were refused")
	}
	if c.admits(running(digest, nil, []string{"PATH=/bin", "HOME=/", "LD_PRELOAD=/evil.so"})) {
		t.Error("an injected environment name was admitted")
	}
}

// An enforcer that cannot see a field leaves it nil. That is not a violation —
// the host-side NRI plugin gates images on a node CVM and never sees a guest's
// mount table, and refusing there would deny every pod it checks.
func TestUnobservedMountsAreNotViolations(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts"}},
		EnvPolicy{Policy: PolicyAny})

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
func TestMountDestinationsAreOrderIndependent(t *testing.T) {
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/b", "/a", "/b"}},
		EnvPolicy{Policy: PolicyAny})

	if got := strings.Join(c.Mounts.Destinations, ","); got != "/a,/b" {
		t.Errorf("destinations = %q, want sorted and deduplicated", got)
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

// sandboxedContainer builds a container whose mount policy is the node-as-CVM
// rule over destinations, with reviews attached to the ones named.
func sandboxedContainer(t *testing.T, destinations []string, reviews map[string]string) Container {
	t.Helper()
	return containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: destinations, Sandboxed: true, Reviews: reviews},
		EnvPolicy{Policy: PolicyAny})
}

func observed(digest string, mounts ...ObservedMount) RunningContainer {
	return RunningContainer{Digest: digest, Mounts: mounts}
}

// The threat the classification exists for: a ConfigMap the operator writes,
// bound over a path the loader reads before the reviewed code runs.
func TestSandboxedMountPolicy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	const dataDest = DataMountPrefix + "config"
	c := sandboxedContainer(t,
		[]string{dataDest, "/var/cache/nginx"},
		map[string]string{dataDest: "yaml the app parses; loads no modules"})

	for _, tc := range []struct {
		name  string
		mount ObservedMount
		admit bool
	}{
		{"reviewed data destination", ObservedMount{Destination: dataDest, Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~configmap/cfg", Class: MountData}, true},
		{"configmap over the loader preload file", ObservedMount{Destination: "/etc/ld.so.preload", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~configmap/cfg", Class: MountData}, false},
		{"data outside the prefix", ObservedMount{Destination: "/var/cache/nginx", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~secret/s", Class: MountData}, false},
		{"emptyDir at a listed destination", ObservedMount{Destination: "/var/cache/nginx", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~empty-dir/cache", Class: MountEmptyDir}, true},
		{"emptyDir at an unlisted destination", ObservedMount{Destination: "/usr/local/lib", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~empty-dir/cache", Class: MountEmptyDir}, false},
		{"platform mount needs no entry", ObservedMount{Destination: "/etc/hosts", Source: "/var/lib/kubelet/pods/u/etc-hosts", Class: MountPlatform}, true},
		{"host path at a listed destination", ObservedMount{Destination: dataDest, Source: "/etc", Class: MountHost}, false},
		{"class this policy has never heard of", ObservedMount{Destination: dataDest, Source: "/x", Class: MountClass("gadget")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.admits(observed(digest, tc.mount)); got != tc.admit {
				t.Errorf("admits(%+v) = %v, want %v", tc.mount, got, tc.admit)
			}
		})
	}
}

// A destination listed with no review can hold an emptyDir but never operator
// content: the review is what says bytes there cannot name code.
func TestSandboxedDataNeedsAReview(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	const dest = DataMountPrefix + "config"
	c := sandboxedContainer(t, []string{dest}, nil)

	if c.admits(observed(digest, ObservedMount{Destination: dest, Class: MountData})) {
		t.Error("operator content was admitted at an unreviewed destination")
	}
	if !c.admits(observed(digest, ObservedMount{Destination: dest, Class: MountEmptyDir})) {
		t.Error("an emptyDir was refused at a listed destination")
	}
}

// An enforcer that reports destinations without saying who staged them gets the
// containment check the field meant before Sandboxed existed, so a served
// document carrying the marker stays enforceable on a node image that predates
// it rather than denying everything it describes.
func TestSandboxedFallsBackToContainmentForAnUnclassifiedObservation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := sandboxedContainer(t, []string{"/etc/hosts"}, nil)

	if !c.admits(RunningContainer{Digest: digest, BindMounts: []string{"/etc/hosts"}}) {
		t.Error("a listed destination was refused")
	}
	if c.admits(RunningContainer{Digest: digest, BindMounts: []string{"/etc/ld.so.preload"}}) {
		t.Error("an unlisted destination was admitted")
	}
}

// A non-sandboxed exact policy keeps plain containment even against a
// classified observation, so an entry written for the guest monitor is not
// newly refused by the node plugin.
func TestExactWithoutSandboxedIsContainment(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts", "/config"}},
		EnvPolicy{Policy: PolicyAny})

	if !c.admits(observed(digest,
		ObservedMount{Destination: "/etc/hosts", Class: MountPlatform},
		ObservedMount{Destination: "/config", Class: MountData})) {
		t.Error("a destination-listing entry was refused")
	}
	if c.admits(observed(digest, ObservedMount{Destination: "/etc/ld.so.preload", Class: MountData})) {
		t.Error("an unlisted destination was admitted")
	}
}

func TestSandboxedMountPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    MountPolicy
	}{
		{"sandboxed on an any policy", MountPolicy{Policy: PolicyAny, Sandboxed: true}},
		{"reviews on an any policy", MountPolicy{Policy: PolicyAny, Reviews: map[string]string{"/x": "why"}}},
		{"review for an unlisted destination", MountPolicy{Policy: PolicyExact, Destinations: []string{"/a"}, Reviews: map[string]string{"/b": "why"}}},
		{"blank review", MountPolicy{Policy: PolicyExact, Destinations: []string{"/a"}, Reviews: map[string]string{"/a": "  "}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Container{Digest: mustDigest(t, "sha256:"+strings.Repeat("a", 64)), Mounts: tc.p}
			if err := normalizeContainers("w", "containers", []Container{c}); err == nil {
				t.Error("normalize accepted an invalid mount policy")
			}
		})
	}
}
