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
	classified := []ObservedMount{}
	for _, destination := range mounts {
		classified = append(classified, ObservedMount{Destination: destination, Class: MountEmptyDir, Storage: MountMemory})
	}
	return RunningContainer{Digest: digest, Mounts: classified, Env: observed}
}

// The threat this policy exists for: the host stages bytes in the sandbox
// seeding directory (a legitimate CopyFile destination) and binds them over a
// path inside an allowlisted image, so the container runs host code while every
// digest still reports as admitted.
func TestMountPolicyRefusesAnUndeclaredDestination(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts"}},
		EnvPolicy{Policy: PolicyAny})

	if !c.admits(running(digest, []string{"/etc/hosts"}, nil)) {
		t.Error("a declared destination was refused")
	}
	if c.admits(running(digest, []string{"/etc/hosts", "/usr/local/bin/get-cert"}, nil)) {
		t.Error("a bind over an image path was admitted")
	}
}

// An absent mount policy permits only node-required mounts.
func TestAbsentMountPolicyDefaultsToDeny(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t, MountPolicy{}, EnvPolicy{})

	if c.Mounts.Policy != PolicyDeny || c.Env.Policy != PolicyAny {
		t.Fatalf("normalized to %q/%q, want deny/any", c.Mounts.Policy, c.Env.Policy)
	}
	if c.admits(running(digest, []string{"/anything", "/at/all"}, nil)) {
		t.Error("an absent policy admitted an operator mount")
	}
}

func TestDenyMountPolicyAdmitsOnlyObservedPlatformMounts(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t, MountPolicy{Policy: PolicyDeny}, EnvPolicy{Policy: PolicyAny})
	if c.admits(RunningContainer{Digest: digest}) {
		t.Fatal("missing mount evidence satisfied deny")
	}
	if !c.admits(RunningContainer{Digest: digest, Mounts: []ObservedMount{}}) {
		t.Fatal("observed empty mount table was refused")
	}
	if !c.admits(observed(digest, ObservedMount{Destination: "/etc/hosts", Class: MountPlatform})) {
		t.Fatal("required node mount was refused")
	}
	if c.admits(observed(digest, ObservedMount{Destination: "/config", Class: MountEmptyDir, Storage: MountMemory})) {
		t.Fatal("operator-selected mount satisfied deny")
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

// A constrained mount policy requires mount evidence at release time.
func TestUnobservedMountsCannotSatisfyExact(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts"}},
		EnvPolicy{Policy: PolicyAny})

	if c.admits(RunningContainer{Digest: digest}) {
		t.Error("an unobserved mount table satisfied exact policy")
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

// exactMountContainer builds a classified policy with reviewed data destinations.
func exactMountContainer(t *testing.T, destinations []string, reviews map[string]string) Container {
	t.Helper()
	return containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: destinations, Reviews: reviews},
		EnvPolicy{Policy: PolicyAny})
}

func observed(digest string, mounts ...ObservedMount) RunningContainer {
	return RunningContainer{Digest: digest, Mounts: mounts}
}

// The threat the classification exists for: a ConfigMap the operator writes,
// bound over a path the loader reads before the reviewed code runs.
func TestExactMountPolicy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	const dataDest = "/mnt/c8s-data/config"
	c := exactMountContainer(t,
		[]string{dataDest, "/var/cache/nginx"},
		map[string]string{dataDest: "yaml the app parses; loads no modules"})

	for _, tc := range []struct {
		name  string
		mount ObservedMount
		admit bool
	}{
		{"reviewed data destination", ObservedMount{Destination: dataDest, Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~configmap/cfg", Class: MountData, Storage: MountMemory}, true},
		{"emptyDir cannot replace reviewed data", ObservedMount{Destination: dataDest, Class: MountEmptyDir, Storage: MountMemory}, false},
		{"encrypted data destination", ObservedMount{Destination: dataDest, Class: MountData, Storage: MountEncrypted}, true},
		{"unproven data storage", ObservedMount{Destination: dataDest, Class: MountData, Storage: MountUnknown}, false},
		{"configmap over the loader preload file", ObservedMount{Destination: "/etc/ld.so.preload", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~configmap/cfg", Class: MountData, Storage: MountMemory}, false},
		{"data outside the prefix", ObservedMount{Destination: "/var/cache/nginx", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~secret/s", Class: MountData, Storage: MountMemory}, false},
		{"emptyDir at a listed destination", ObservedMount{Destination: "/var/cache/nginx", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~empty-dir/cache", Class: MountEmptyDir, Storage: MountMemory}, true},
		{"plaintext emptyDir at a listed destination", ObservedMount{Destination: "/var/cache/nginx", Class: MountEmptyDir, Storage: MountUnknown}, false},
		{"emptyDir at an unlisted destination", ObservedMount{Destination: "/usr/local/lib", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~empty-dir/cache", Class: MountEmptyDir, Storage: MountMemory}, false},
		{"platform mount needs no entry", ObservedMount{Destination: "/etc/hosts", Source: "/var/lib/kubelet/pods/u/etc-hosts", Class: MountPlatform}, true},
		{"host path at a listed destination", ObservedMount{Destination: dataDest, Source: "/etc", Class: MountHost}, false},
		{"class this policy has never heard of", ObservedMount{Destination: dataDest, Source: "/x", Class: MountClass("gadget")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mounts := []ObservedMount{tc.mount}
			if tc.mount.Destination != dataDest || tc.mount.Class == MountPlatform {
				mounts = append(mounts, ObservedMount{Destination: dataDest, Class: MountData, Storage: MountMemory})
			}
			if tc.mount.Destination != "/var/cache/nginx" || tc.mount.Class == MountPlatform {
				mounts = append(mounts, ObservedMount{Destination: "/var/cache/nginx", Class: MountEmptyDir, Storage: MountMemory})
			}
			if got := c.admits(observed(digest, mounts...)); got != tc.admit {
				t.Errorf("admits(%+v) = %v, want %v", tc.mount, got, tc.admit)
			}
		})
	}
}

// A destination listed with no review can hold an emptyDir but never operator
// content: the review is what says bytes there cannot name code.
func TestExactDataNeedsAReview(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	const dest = "/mnt/c8s-data/config"
	c := exactMountContainer(t, []string{dest}, nil)

	if c.admits(observed(digest, ObservedMount{Destination: dest, Class: MountData, Storage: MountMemory})) {
		t.Error("operator content was admitted at an unreviewed destination")
	}
	if !c.admits(observed(digest, ObservedMount{Destination: dest, Class: MountEmptyDir, Storage: MountMemory})) {
		t.Error("an emptyDir was refused at a listed destination")
	}
}

// A destination-only or absent observation cannot satisfy exact policy.
func TestExactRequiresClassifiedObservation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := exactMountContainer(t, []string{"/etc/hosts"}, nil)

	if c.admits(RunningContainer{Digest: digest}) {
		t.Error("missing classification satisfied exact policy")
	}
}

func TestExactAlwaysRequiresDataReview(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	c := containerWith(t,
		MountPolicy{Policy: PolicyExact, Destinations: []string{"/etc/hosts", "/config"}},
		EnvPolicy{Policy: PolicyAny})

	if c.admits(observed(digest,
		ObservedMount{Destination: "/etc/hosts", Class: MountPlatform},
		ObservedMount{Destination: "/config", Class: MountData, Storage: MountMemory})) {
		t.Error("unreviewed data was admitted")
	}
	if c.admits(observed(digest, ObservedMount{Destination: "/etc/ld.so.preload", Class: MountData, Storage: MountMemory})) {
		t.Error("an unlisted destination was admitted")
	}
}

func TestExactMountPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    MountPolicy
	}{
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
