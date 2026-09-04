package helmchart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

// The node image bakes a ValidatingAdmissionPolicy that keeps the restricted
// PodSecurity floor an invariant for namespace-scoped tenants. The manifest is
// applied by RKE2, not the chart, so it is read from the image tree here.
const psaLevelPolicyPath = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/psa-level-policy.yaml"

func loadPSALevelPolicy(t *testing.T) (admissionregv1.ValidatingAdmissionPolicy, admissionregv1.ValidatingAdmissionPolicyBinding) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(psaLevelPolicyPath))
	if err != nil {
		t.Fatalf("read %s: %v", psaLevelPolicyPath, err)
	}
	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, string(raw), "ValidatingAdmissionPolicy", "confos-psa-level", &vap) {
		t.Fatal("ValidatingAdmissionPolicy confos-psa-level not in manifest")
	}
	var binding admissionregv1.ValidatingAdmissionPolicyBinding
	if !findDoc(t, string(raw), "ValidatingAdmissionPolicyBinding", "confos-psa-level", &binding) {
		t.Fatal("ValidatingAdmissionPolicyBinding confos-psa-level not in manifest")
	}
	return vap, binding
}

func TestPSALevelPolicyShape(t *testing.T) {
	vap, binding := loadPSALevelPolicy(t)
	if vap.Spec.FailurePolicy == nil || *vap.Spec.FailurePolicy != admissionregv1.Fail {
		t.Error("failurePolicy must be Fail so an evaluation error denies the write")
	}
	if len(vap.Spec.Validations) != 1 {
		t.Fatalf("expected one validation, got %d", len(vap.Spec.Validations))
	}
	// Labels are writable through the status and finalize subresources too,
	// and kubectl label is an UPDATE.
	want := map[string]bool{"namespaces": false, "namespaces/status": false, "namespaces/finalize": false}
	ops := map[admissionregv1.OperationType]bool{}
	for _, r := range vap.Spec.MatchConstraints.ResourceRules {
		for _, res := range r.Resources {
			if _, ok := want[res]; ok {
				want[res] = true
			}
		}
		for _, op := range r.Operations {
			ops[op] = true
		}
	}
	for res, seen := range want {
		if !seen {
			t.Errorf("matchConstraints does not name %s", res)
		}
	}
	for _, op := range []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update} {
		if !ops[op] {
			t.Errorf("matchConstraints does not match %s", op)
		}
	}
	if binding.Spec.PolicyName != vap.Name {
		t.Errorf("binding names policy %q, want %q", binding.Spec.PolicyName, vap.Name)
	}
	if len(binding.Spec.ValidationActions) != 1 || binding.Spec.ValidationActions[0] != admissionregv1.Deny {
		t.Errorf("binding must Deny, got %v", binding.Spec.ValidationActions)
	}
}

// evalPSALevel runs the policy's expression with the given new and old
// namespace and authorizer verdict. oldObject is nil on CREATE. The authorizer
// is modelled as a dyn value whose chain ends in `allowed`.
func evalPSALevel(t *testing.T, expr string, object, oldObject map[string]any, allowed bool) bool {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("authorizer", cel.DynType),
		cel.OptionalTypes(),
	)
	if err != nil {
		t.Fatalf("cel env: %v", err)
	}
	// The k8s authorizer chain is not a CEL library; substitute a map lookup
	// with the same truth value so the rest of the expression is exercised.
	const chain = "authorizer.group('confidential.ai').resource('podsecurityexemptions').check('grant').allowed()"
	if !strings.Contains(expr, chain) {
		t.Fatalf("expression does not check the podsecurityexemptions grant: %q", expr)
	}
	expr = strings.ReplaceAll(expr, chain, "authorizer.allowed")
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("cel compile: %v", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("cel program: %v", err)
	}
	var old any
	if oldObject != nil {
		old = oldObject
	}
	out, _, err := prg.Eval(map[string]any{
		"object":     object,
		"oldObject":  old,
		"authorizer": map[string]any{"allowed": allowed},
	})
	if err != nil {
		t.Fatalf("cel eval: %v", err)
	}
	return out.Value() == true
}

func nsWithLabels(labels map[string]any) map[string]any {
	md := map[string]any{"name": "tenant"}
	if labels != nil {
		md["labels"] = labels
	}
	return map[string]any{"metadata": md}
}

func TestPSALevelPolicyExpression(t *testing.T) {
	vap, _ := loadPSALevelPolicy(t)
	expr := vap.Spec.Validations[0].Expression
	const enforce = "pod-security.kubernetes.io/enforce"
	const version = "pod-security.kubernetes.io/enforce-version"
	privileged := map[string]any{enforce: "privileged"}
	for _, tc := range []struct {
		name    string
		object  map[string]any
		old     map[string]any
		allowed bool
		want    bool
	}{
		{"create without labels", nsWithLabels(nil), nil, false, true},
		{"create with unrelated labels", nsWithLabels(map[string]any{"team": "a"}), nil, false, true},
		{"create restricted", nsWithLabels(map[string]any{enforce: "restricted"}), nil, false, true},
		{"create restricted latest", nsWithLabels(map[string]any{enforce: "restricted", version: "latest"}), nil, false, true},
		{"tenant creates privileged", nsWithLabels(privileged), nil, false, false},
		{"tenant creates baseline", nsWithLabels(map[string]any{enforce: "baseline"}), nil, false, false},
		{"tenant pins old version", nsWithLabels(map[string]any{enforce: "restricted", version: "v1.0"}), nil, false, false},
		{"tenant pins old version without level", nsWithLabels(map[string]any{version: "v1.0"}), nil, false, false},
		{"tenant lowers on update", nsWithLabels(privileged), nsWithLabels(nil), false, false},
		{"tenant lowers on update from restricted", nsWithLabels(privileged), nsWithLabels(map[string]any{enforce: "restricted"}), false, false},
		{"tenant raises to restricted", nsWithLabels(map[string]any{enforce: "restricted"}), nsWithLabels(privileged), false, true},
		{"tenant removes privileged label", nsWithLabels(nil), nsWithLabels(privileged), false, true},
		{"unrelated update of privileged namespace", nsWithLabels(map[string]any{enforce: "privileged", "team": "a"}), nsWithLabels(privileged), false, true},
		{"status update keeps privileged", nsWithLabels(privileged), nsWithLabels(privileged), false, true},
		{"granter creates privileged", nsWithLabels(privileged), nil, true, true},
		{"granter lowers on update", nsWithLabels(privileged), nsWithLabels(nil), true, true},
		{"granter pins old version", nsWithLabels(map[string]any{enforce: "restricted", version: "v1.25"}), nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalPSALevel(t, expr, tc.object, tc.old, tc.allowed); got != tc.want {
				t.Errorf("allowed=%v, want %v", got, tc.want)
			}
		})
	}
}
