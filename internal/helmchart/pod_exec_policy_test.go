package helmchart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

// The node image keeps the kubelet debugging handlers on so `kubectl logs`
// works for the log-reader credential, and bakes this policy so the other
// handlers (exec, attach, port-forward) and ephemeral containers stay closed
// at the apiserver for every principal. Applied by RKE2, not the chart, so it
// is read from the image tree here like psa-level-policy.
const podExecPolicyPath = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/pod-exec-policy.yaml"

func TestPodExecPolicyShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(podExecPolicyPath))
	if err != nil {
		t.Fatalf("read %s: %v", podExecPolicyPath, err)
	}
	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, string(raw), "ValidatingAdmissionPolicy", "confos-pod-exec", &vap) {
		t.Fatal("ValidatingAdmissionPolicy confos-pod-exec not in manifest")
	}
	var binding admissionregv1.ValidatingAdmissionPolicyBinding
	if !findDoc(t, string(raw), "ValidatingAdmissionPolicyBinding", "confos-pod-exec", &binding) {
		t.Fatal("ValidatingAdmissionPolicyBinding confos-pod-exec not in manifest")
	}
	if vap.Spec.FailurePolicy == nil || *vap.Spec.FailurePolicy != admissionregv1.Fail {
		t.Error("failurePolicy must be Fail so an evaluation error denies the request")
	}
	// exec/attach/port-forward are CONNECT on their subresources; ephemeral
	// containers are an UPDATE on theirs (kubectl debug). Each subresource
	// must be matched under the operation the apiserver actually reports.
	want := map[string]admissionregv1.OperationType{
		"pods/exec":                admissionregv1.Connect,
		"pods/attach":              admissionregv1.Connect,
		"pods/portforward":         admissionregv1.Connect,
		"pods/ephemeralcontainers": admissionregv1.Update,
	}
	for _, r := range vap.Spec.MatchConstraints.ResourceRules {
		for _, res := range r.Resources {
			op, ok := want[res]
			if !ok {
				t.Errorf("matchConstraints names unexpected resource %q", res)
				continue
			}
			for _, have := range r.Operations {
				if have == op || have == admissionregv1.OperationAll {
					delete(want, res)
				}
			}
		}
	}
	for res, op := range want {
		t.Errorf("matchConstraints does not match %s on %s", op, res)
	}
	if len(vap.Spec.Validations) != 1 {
		t.Fatalf("expected one validation, got %d", len(vap.Spec.Validations))
	}
	// The expression is a constant deny; it must compile and evaluate false
	// with no variables, so it cannot error into the failurePolicy path.
	env, err := cel.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	ast, iss := env.Compile(vap.Spec.Validations[0].Expression)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("cel compile: %v", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := prg.Eval(map[string]any{})
	if err != nil {
		t.Fatalf("cel eval: %v", err)
	}
	if out.Value() != false {
		t.Errorf("validation evaluates to %v, want false (deny)", out.Value())
	}
	if vap.Spec.Validations[0].Message == "" {
		t.Error("validation has no message")
	}
	if binding.Spec.PolicyName != vap.Name {
		t.Errorf("binding names policy %q, want %q", binding.Spec.PolicyName, vap.Name)
	}
	if len(binding.Spec.ValidationActions) != 1 || binding.Spec.ValidationActions[0] != admissionregv1.Deny {
		t.Errorf("binding must Deny, got %v", binding.Spec.ValidationActions)
	}
	if binding.Spec.MatchResources != nil {
		t.Error("binding must not narrow the policy: every principal, cluster-admin included, is denied")
	}
}
