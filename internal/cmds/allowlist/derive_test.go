package allowlist

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const testDigest = "sha256:effd250754b8a70517c27eab8f18463b395a7b2a8e868fd919226c3180636939"
const testImage = "nvcr.io/nvidia/ai-dynamo/vllm-runtime@" + testDigest

// deployJSON is a Deployment carrying an init container, a container with a
// command and no args, and a container with both. That combination is what a
// hand-written entry gets wrong in practice.
func deployJSON() string {
	return `{
      "kind": "Deployment",
      "spec": {"template": {"spec": {
        "initContainers": [
          {"name": "seed", "image": "` + testImage + `",
           "command": ["sh", "-c", "cp -an /a/. /seed/"]}
        ],
        "containers": [
          {"name": "frontend", "image": "` + testImage + `",
           "command": ["python3", "-m", "dynamo.frontend"]},
          {"name": "worker", "image": "` + testImage + `",
           "command": ["sh"], "args": ["-c", "exec python3 -m dynamo.vllm"]}
        ]}}}}`
}

func runDerive(t *testing.T, stdin string, args ...string) (map[string]pkgallowlist.Workload, error) {
	t.Helper()
	cmd := newWorkloadDeriveCmd(&options{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		return nil, err
	}
	var got map[string]pkgallowlist.Workload
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("derived output is not a workload map: %v\n%s", err, out.String())
	}
	return got, nil
}

func TestDeriveCoversInitContainers(t *testing.T) {
	got, err := runDerive(t, deployJSON(), "dynamo", "-")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	w, ok := got["dynamo"]
	if !ok {
		t.Fatalf("entry not keyed by name: %v", got)
	}
	// CDS matches the whole candidate set, so an undeclared init container
	// refuses every release with "no workload entry matches the running
	// containers".
	if len(w.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(w.InitContainers))
	}
	if len(w.Containers) != 2 {
		t.Fatalf("containers = %d, want 2", len(w.Containers))
	}
}

func TestDeriveArgvPolicies(t *testing.T) {
	got, _ := runDerive(t, deployJSON(), "dynamo", "-")
	w := got["dynamo"]

	// A command with no args is Deny. Exact would be rejected on apply
	// ("exact policy requires a non-empty argv") and Any would be looser than
	// what the container runs.
	if p := w.Containers[0].Args.Policy; p != pkgallowlist.PolicyDeny {
		t.Errorf("frontend args policy = %q, want %q", p, pkgallowlist.PolicyDeny)
	}
	if p := w.Containers[1].Args.Policy; p != pkgallowlist.PolicyExact {
		t.Errorf("worker args policy = %q, want %q", p, pkgallowlist.PolicyExact)
	}
	if got, want := w.Containers[1].Args.Argv, []string{"-c", "exec python3 -m dynamo.vllm"}; !equalArgv(got, want) {
		t.Errorf("worker argv = %v, want %v", got, want)
	}
	if p := w.InitContainers[0].Command.Policy; p != pkgallowlist.PolicyExact {
		t.Errorf("init command policy = %q, want %q", p, pkgallowlist.PolicyExact)
	}
}

func TestDeriveSecretsOnlyWhenAsked(t *testing.T) {
	got, _ := runDerive(t, deployJSON(), "dynamo", "-")
	if got["dynamo"].Secrets != nil {
		t.Errorf("secrets block emitted without --secret-read")
	}

	got, _ = runDerive(t, deployJSON(), "dynamo", "-", "--secret-read", "/dynamo/volumes/w235")
	s := got["dynamo"].Secrets
	if s == nil {
		t.Fatal("no secrets block with --secret-read")
	}
	if s.Policy != pkgallowlist.PolicyAllow || len(s.Read) != 1 || s.Read[0] != "/dynamo/volumes/w235" {
		t.Errorf("secrets = %+v", s)
	}
}

func TestDeriveAcceptsABarePod(t *testing.T) {
	pod := `{"kind":"Pod","spec":{"containers":[{"name":"c","image":"` + testImage + `","command":["sleep","inf"]}]}}`
	got, err := runDerive(t, pod, "p", "-")
	if err != nil {
		t.Fatalf("derive pod: %v", err)
	}
	if len(got["p"].Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(got["p"].Containers))
	}
}

func TestDeriveBindsInjectedHelperFinalHostIPArgv(t *testing.T) {
	pod := `{"kind":"Pod","spec":{"containers":[{"name":"c8s-cert","image":"` + testImage + `",
		"command":["/c8s","get-cert"],"args":["--attestation-api-url=http://$(HOST_IP):8400"],
		"env":[{"name":"HOST_IP","valueFrom":{"fieldRef":{"fieldPath":"status.hostIP"}}}]}]}}`
	got, err := runDerive(t, pod, "p", "-")
	if err != nil {
		t.Fatal(err)
	}
	bindings := got["p"].Containers[0].Args.EnvBindings
	if len(bindings) != 1 || bindings[0].Index != 0 || len(bindings[0].Names) != 1 || bindings[0].Names[0] != "HOST_IP" {
		t.Fatalf("helper argv bindings = %+v", bindings)
	}
	bad := strings.Replace(pod, `"valueFrom":{"fieldRef":{"fieldPath":"status.hostIP"}}`, `"value":"attacker"`, 1)
	if _, err := runDerive(t, bad, "p", "-"); err == nil {
		t.Fatal("helper dynamic argv accepted an operator-controlled env value")
	}
	escaped := strings.Replace(pod, "$(HOST_IP)", "$$(HOST_IP)", 1)
	if _, err := runDerive(t, escaped, "p", "-"); err == nil {
		t.Fatal("helper dynamic argv accepted an escaped kubelet placeholder")
	} else if !strings.Contains(err.Error(), "leaves literal") {
		t.Fatalf("escaped placeholder error = %v", err)
	}
}

func TestDeriveRejectsUnpinnedImage(t *testing.T) {
	bad := `{"kind":"Pod","spec":{"containers":[{"name":"c","image":"busybox:latest","command":["sh"]}]}}`
	if _, err := runDerive(t, bad, "p", "-"); err == nil {
		t.Fatal("accepted an image with no digest")
	} else if !strings.Contains(err.Error(), "not pinned by digest") {
		t.Errorf("error = %v, want a digest complaint", err)
	}
}

func TestDeriveRejectsObjectWithoutContainers(t *testing.T) {
	if _, err := runDerive(t, `{"kind":"ConfigMap","spec":{}}`, "x", "-"); err == nil {
		t.Fatal("accepted an object with no pod spec")
	} else if !strings.Contains(err.Error(), "carries no containers") {
		t.Errorf("error = %v", err)
	}
}

func equalArgv(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
