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
	for _, id := range []string{
		"6d7f5f7bd6e6b1f3a2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6",
		"aa-1", "aa_1", "aa.1", "ab", "a", "-ab", ".ab", "aa/1", "аа1", "",
		strings.Repeat("a", 128), strings.Repeat("a", 129),
	} {
		if policy.MatchString(id) && !ValidContainerID(id) {
			t.Errorf("policy admits container id %q but ValidContainerID rejects it: nothing would decide on that container", id)
		}
	}
	// The watchers skip kata's own directories by name, which is only safe
	// because the policy refuses them as container ids.
	for _, name := range ReservedBundleNames {
		if !strings.Contains(readPolicy(t), `"`+name+`"`) {
			t.Errorf("the baked policy does not reserve the bundle name %q", name)
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
