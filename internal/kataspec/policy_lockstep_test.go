package kataspec

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The baked kata-agent policy decides which CreateContainerRequests reach the
// guest; this package decides which of the resulting bundles policy-monitor and
// rtmr3-measurer resolve. Where the two describe the same set they must agree:
// a container the policy admits but this package filters out is one nothing
// makes a decision on, and a reference the policy accepts but PullDigest
// rejects is a container killed for an image the guest was told to run.
//
// The policy is the source of truth here — these tests read the shipped file
// and re-run its patterns against the Go implementation.

const policyPath = "../../kata-guest-base/extra/etc/kata-opa/default-policy.rego"

func readPolicy(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(policyPath))
	if err != nil {
		t.Fatalf("read baked policy: %v", err)
	}
	return string(body)
}

// extractPattern pulls the single regex.match pattern applied to subject.
func extractPattern(t *testing.T, policy, subject string) *regexp.Regexp {
	t.Helper()
	re := regexp.MustCompile(`regex\.match\("([^"]+)", ` + regexp.QuoteMeta(subject) + `\)`)
	m := re.FindStringSubmatch(policy)
	if m == nil {
		t.Fatalf("no regex.match(..., %s) in the baked policy", subject)
	}
	got, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("policy pattern for %s does not compile in Go: %v", subject, err)
	}
	return got
}

func TestContainerIDAgreesWithBakedPolicy(t *testing.T) {
	policy := extractPattern(t, readPolicy(t), "input.container_id")
	hex64 := strings.Repeat("a", 64)
	for _, id := range []string{
		"6d7f5f7bd6e6b1f3a2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6", hex64,
		"aa-1", "aa_1", "aa.1", "ab", "a", "-ab", ".ab", "aa/1", "аа1", "",
	} {
		if policy.MatchString(id) && !ValidContainerID(id) {
			t.Errorf("policy admits container id %q but ValidContainerID rejects it: nothing would decide on that container", id)
		}
	}

	// Both sides admit only what the CRI generates. A shorter id can name a
	// systemd unit cgroup, and the kill path resolves a denied container's
	// cgroup by name; kata's own bundle directories are excluded by the same
	// pattern rather than by a separate rule.
	for _, id := range []string{
		"init", "ab", "shared", "sandbox", "image",
		hex64[:63], hex64 + "a", strings.ToUpper(hex64),
	} {
		if policy.MatchString(id) {
			t.Errorf("baked policy admits container id %q", id)
		}
		if ValidContainerID(id) {
			t.Errorf("ValidContainerID accepts container id %q", id)
		}
	}
}

func TestPullDigestAgreesWithBakedPolicy(t *testing.T) {
	policy := extractPattern(t, readPolicy(t), "pull.source")
	digest := strings.Repeat("a", 64)
	for _, ref := range []string{
		"ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
		"nginx:1.27-alpine",
		"sha256:" + digest,
		"x@sha256:" + strings.ToUpper(digest),
		"x@sha256:" + digest + "extra",
		"pause",
		"",
	} {
		_, ok := PullDigest(map[string]string{PullReferenceKey: ref})
		if policy.MatchString(ref) != ok {
			t.Errorf("reference %q: policy admits=%v, PullDigest ok=%v", ref, policy.MatchString(ref), ok)
		}
	}
}

// containerd is the only CRI in this shape, so an honest CreateContainerRequest
// never carries the CRI-O container-type key; the policy denies one that does.
func TestBakedPolicyRejectsCRIOContainerTypeMarker(t *testing.T) {
	if !strings.Contains(readPolicy(t), `not input.OCI.Annotations["io.kubernetes.cri-o.ContainerType"]`) {
		t.Error("baked policy does not reject the CRI-O container-type marker")
	}
}

// sandboxConjuncts extracts the annotation equalities the baked policy's
// sandbox_annotations rule conjoins. The read is deliberately strict: a rule
// edited into any other shape fails here rather than comparing a partial
// predicate.
func sandboxConjuncts(t *testing.T, policy string) map[string]string {
	t.Helper()
	rule := regexp.MustCompile(`sandbox_annotations if \{\n(?:\t[^\n]+\n)+\}`)
	blocks := rule.FindAllString(policy, -1)
	if len(blocks) != 1 {
		t.Fatalf("baked policy has %d sandbox_annotations rules, want exactly one (a second one would OR another predicate past this test)", len(blocks))
	}
	block := regexp.MustCompile(`\{\n((?:\t[^\n]+\n)+)\}`).FindStringSubmatch(blocks[0])
	equality := regexp.MustCompile(`^input\.OCI\.Annotations\["([^"]+)"\] == "([^"]+)"$`)
	pairs := map[string]string{}
	for _, l := range strings.Split(strings.TrimRight(block[1], "\n"), "\n") {
		m := equality.FindStringSubmatch(strings.TrimPrefix(l, "\t"))
		if m == nil {
			t.Fatalf("sandbox_annotations carries a line the lockstep test cannot read: %q", l)
		}
		pairs[m[1]] = m[2]
	}
	return pairs
}

// IsSandbox decides which containers policy-monitor exempts from digest
// enforcement, and the baked policy's sandbox_annotations decides which
// containers kata runs the measured pause for; the two predicates must accept
// identical annotation sets. Machine-compare them over every combination of
// the type markers a host can write — including the CRI-O key, so a predicate
// that reads it disagrees with the side that does not. A one-sided edit to
// either predicate flips at least one row.
func TestSandboxPredicateAgreesWithBakedPolicy(t *testing.T) {
	conjuncts := sandboxConjuncts(t, readPolicy(t))
	const crioKey = "io.kubernetes.cri-o.ContainerType"

	kataValues := []string{"", "pod_sandbox", "pod_container", "bogus"}
	criValues := []string{"", "sandbox", "container", "SANDBOX"}
	crioValues := []string{"", "sandbox", "container"}

	for _, kata := range kataValues {
		for _, cri := range criValues {
			for _, crio := range crioValues {
				annotations := map[string]string{}
				for key, value := range map[string]string{
					kataContainerTypeKey: kata,
					criContainerTypeKey:  cri,
					crioKey:              crio,
				} {
					if value != "" {
						annotations[key] = value
					}
				}
				policy := true
				for key, want := range conjuncts {
					if annotations[key] != want {
						policy = false
						break
					}
				}
				if got := IsSandbox(annotations); got != policy {
					t.Errorf("annotations %v: IsSandbox = %v, sandbox_annotations = %v", annotations, got, policy)
				}
			}
		}
	}
}

// A rule that silently reverts to `default … := true` is a no-op with no
// symptom, so pin the decisions the guest's integrity rests on.
func TestBakedPolicyKeepsItsFailClosedDefaults(t *testing.T) {
	policy := readPolicy(t)
	for _, want := range []string{
		"default CreateContainerRequest := false",
		"default CreateSandboxRequest := false",
		"default UpdateEphemeralMountsRequest := false",
		"default CopyFileRequest := false",
		"default SetPolicyRequest := false",
		"default ExecProcessRequest := false",
		"default ReadStreamRequest := false",
		"default WriteStreamRequest := false",
		// regorus defaults to Rego v0, where rule bodies need these.
		"import future.keywords.every",
		"import future.keywords.if",
		"import future.keywords.in",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("baked policy is missing %q", want)
		}
	}
	// AllowRequestsFailingPolicy turns every evaluation failure into an allow.
	if strings.Contains(policy, "AllowRequestsFailingPolicy") {
		t.Error("baked policy defines AllowRequestsFailingPolicy; that admits every request the engine cannot evaluate")
	}
}
