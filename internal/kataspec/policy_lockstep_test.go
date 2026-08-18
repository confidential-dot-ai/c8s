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
	return stripComments(string(body))
}

// stripComments removes `#` comments, which carry no semantics: left in, a
// comment line can hide an else chain from the extractors or pose as a rule.
// String and raw-string literals are preserved.
func stripComments(policy string) string {
	var out strings.Builder
	out.Grow(len(policy))
	inString, inRaw := false, false
	for i := 0; i < len(policy); i++ {
		c := policy[i]
		switch {
		case inString:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(policy) {
				i++
				out.WriteByte(policy[i])
			} else if c == '"' {
				inString = false
			}
		case inRaw:
			out.WriteByte(c)
			if c == '`' {
				inRaw = false
			}
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '`':
			inRaw = true
			out.WriteByte(c)
		case c == '#':
			for i+1 < len(policy) && policy[i+1] != '\n' {
				i++
			}
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
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

// ruleBodies extracts the bodies of the policy's definitions of name from
// comment-stripped text. The read is deliberately strict, and the lockstep
// tests below rely on it: a definition counts however it is indented (the
// fmt gate in make policy-test normalises heads to column 0), each
// definition must be the braced, tab-indented shape these tests parse, and
// an else chain after a body fails the test rather than going unread.
func ruleBodies(t *testing.T, policy, name string) []string {
	t.Helper()
	defs := regexp.MustCompile(`(?m)^[ \t]*`+regexp.QuoteMeta(name)+`(\([^)]*\))?\s+(if|:=)`).FindAllStringIndex(policy, -1)
	if len(defs) == 0 {
		t.Fatalf("baked policy defines no %s rule", name)
	}
	body := regexp.MustCompile(regexp.QuoteMeta(name) + `[^\n{]*\{\n((?:\t[^\n]*\n|\n)+)\}`)
	elseChain := regexp.MustCompile(`^\s*else\b`)
	var bodies []string
	for _, def := range defs {
		m := body.FindStringSubmatchIndex(policy[def[0]:])
		if m == nil || m[0] != 0 {
			t.Fatalf("%s is not the braced, tab-indented rule this test reads", name)
		}
		if elseChain.MatchString(policy[def[0]+m[1]:]) {
			t.Fatalf("%s continues in an else chain this test does not read", name)
		}
		bodies = append(bodies, policy[def[0]+m[2]:def[0]+m[3]])
	}
	return bodies
}

// containerd is the only CRI in this shape, so an honest CreateContainerRequest
// never carries the CRI-O container-type key; the policy denies one that does,
// in the OCI annotations and in the guest-pull metadata kata's handler reads
// the marker from. The guards are pinned as lines of the CreateContainerRequest
// body itself — a commented-out or relocated line would still contain the
// substring.
func TestBakedPolicyRejectsCRIOContainerTypeMarker(t *testing.T) {
	bodies := ruleBodies(t, readPolicy(t), "CreateContainerRequest")
	if len(bodies) != 1 {
		t.Fatalf("baked policy has %d CreateContainerRequest rules, want exactly one", len(bodies))
	}
	for _, guard := range []string{
		`not input.OCI.Annotations["io.kubernetes.cri-o.ContainerType"]`,
		`not crio_pull_metadata(pull)`,
	} {
		line := regexp.MustCompile(`(?m)^\t` + regexp.QuoteMeta(guard) + `$`)
		if !line.MatchString(bodies[0]) {
			t.Errorf("CreateContainerRequest does not carry the guard line %q", guard)
		}
	}
}

// pull_source_bound decides what kata runs for an admitted request; its
// sandbox branch is what makes it safe for policy-monitor to exempt the pause
// from digest enforcement, and its workload branch is the only place a
// host-image source may bind. Pin the admission shape that safety rests on:
// exactly two branches, the sandbox one keyed on sandbox_annotations and
// bound to the measured pause, the workload one keyed on
// workload_annotations.
func TestBakedPolicyBindsSandboxPullToPause(t *testing.T) {
	bodies := ruleBodies(t, readPolicy(t), "pull_source_bound")
	if len(bodies) != 2 {
		t.Fatalf("baked policy has %d pull_source_bound branches, want exactly two (another would OR a second source binding past the admission contract)", len(bodies))
	}
	var sandbox []int
	for i, b := range bodies {
		if strings.Contains(b, "\tsandbox_annotations\n") {
			sandbox = append(sandbox, i)
		}
	}
	if len(sandbox) != 1 {
		t.Fatalf("want exactly one pull_source_bound branch keyed on sandbox_annotations, got %d", len(sandbox))
	}
	if !strings.Contains(bodies[sandbox[0]], "\tpull.source == \"pause\"\n") {
		t.Error("the sandbox branch of pull_source_bound does not bind pull.source to the measured pause")
	}
	if !strings.Contains(bodies[1-sandbox[0]], "\tworkload_annotations\n") {
		t.Error("the workload branch of pull_source_bound is not keyed on workload_annotations")
	}
}

// A second workload_annotations definition would OR another predicate into
// the branch that binds a host-image source — the widening half of the
// admission contract. Counted and shape-checked exactly like
// sandbox_annotations.
func TestBakedPolicyDefinesOneWorkloadAnnotations(t *testing.T) {
	bodies := ruleBodies(t, readPolicy(t), "workload_annotations")
	if len(bodies) != 1 {
		t.Fatalf("baked policy has %d workload_annotations rules, want exactly one (a second one would OR another predicate past the admission contract)", len(bodies))
	}
}

// sandboxConjuncts extracts the annotation equalities the baked policy's
// sandbox_annotations rule conjoins. The read is deliberately strict: a rule
// edited into any other shape fails here rather than comparing a partial
// predicate.
func sandboxConjuncts(t *testing.T, policy string) map[string]string {
	t.Helper()
	bodies := ruleBodies(t, policy, "sandbox_annotations")
	if len(bodies) != 1 {
		t.Fatalf("baked policy has %d sandbox_annotations rules, want exactly one (a second one would OR another predicate past this test)", len(bodies))
	}
	equality := regexp.MustCompile(`^input\.OCI\.Annotations\["([^"]+)"\] == "([^"]+)"$`)
	pairs := map[string]string{}
	for _, l := range strings.Split(strings.TrimRight(bodies[0], "\n"), "\n") {
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

	check := func(annotations map[string]string) {
		t.Helper()
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
				check(annotations)
			}
		}
	}

	// "" is the absent sentinel above; a marker present with an empty value
	// is a distinct row the host can write.
	for _, annotations := range []map[string]string{
		{kataContainerTypeKey: ""},
		{criContainerTypeKey: ""},
		{kataContainerTypeKey: "", criContainerTypeKey: "sandbox"},
		{kataContainerTypeKey: "pod_sandbox", criContainerTypeKey: ""},
		{kataContainerTypeKey: "", criContainerTypeKey: "", crioKey: ""},
	} {
		check(annotations)
	}
}

// Spec hooks ride inside an otherwise-admitted CreateContainerRequest;
// Prestart and CreateContainer execute as guest root ahead of the
// admission verdict, the remaining lists after it (CreateRuntime never
// fires in the agent). The guard admits the one shape an honest request
// carries, so a hook list added on a kata bump is covered without naming
// it. Pin it the same way as the CRI-O marker: one no_spec_hooks rule,
// conjoined into CreateContainerRequest — a commented-out or relocated
// line still leaves the substrings present, so read the rule bodies.
func TestBakedPolicyRejectsSpecHooks(t *testing.T) {
	policy := readPolicy(t)

	hookBodies := ruleBodies(t, policy, "no_spec_hooks")
	if len(hookBodies) != 1 {
		t.Fatalf("baked policy has %d no_spec_hooks rules, want exactly one (a second would OR another predicate past the guard)", len(hookBodies))
	}
	guard := regexp.MustCompile(`(?m)^\t` + regexp.QuoteMeta("is_null(input.OCI.Hooks)") + `$`)
	if !guard.MatchString(hookBodies[0]) {
		t.Errorf("no_spec_hooks does not carry the is_null(input.OCI.Hooks) guard; an enumeration of the known hook lists admits an unnamed one")
	}

	containerBodies := ruleBodies(t, policy, "CreateContainerRequest")
	if len(containerBodies) != 1 {
		t.Fatalf("baked policy has %d CreateContainerRequest rules, want exactly one", len(containerBodies))
	}
	if !strings.Contains(containerBodies[0], "\tno_spec_hooks\n") {
		t.Error("CreateContainerRequest does not conjoin no_spec_hooks")
	}
}

// sandboxGuard asserts CreateSandboxRequest conjoins guard as its own line.
// Both callers pin a count() over a key the serializer always emits, which
// upstream genpolicy's CreateSandboxRequest carries verbatim.
func sandboxGuard(t *testing.T, guard string) {
	t.Helper()
	bodies := ruleBodies(t, readPolicy(t), "CreateSandboxRequest")
	if len(bodies) != 1 {
		t.Fatalf("baked policy has %d CreateSandboxRequest rules, want exactly one", len(bodies))
	}
	line := regexp.MustCompile(`(?m)^\t` + regexp.QuoteMeta(guard) + `$`)
	if !line.MatchString(bodies[0]) {
		t.Errorf("CreateSandboxRequest does not carry the guard line %q", guard)
	}
}

// add_hooks arms every container with executables from the guest_hook_path
// directory.
func TestBakedPolicyRejectsGuestHookPath(t *testing.T) {
	sandboxGuard(t, "count(input.guest_hook_path) == 0")
}

// load_kernel_module passes the request's name and parameters to modprobe
// as argv.
func TestBakedPolicyRejectsKernelModules(t *testing.T) {
	sandboxGuard(t, "count(input.kernel_modules) == 0")
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
		"default GetDiagnosticDataRequest := false",
		"default ReseedRandomDevRequest := false",
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
