package helmchart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

// The node image binds cred-release credentials to a bounded ClusterRole and
// bakes this policy so that, whatever RBAC says, no c8s:* principal can write
// where a guard could be disabled or the host reached. Applied by RKE2, not
// the chart, so it is read from the image tree here like psa-level-policy.
const operatorScopePolicyPath = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/operator-scope-policy.yaml"

func loadOperatorScopePolicy(t *testing.T) (admissionregv1.ValidatingAdmissionPolicy, admissionregv1.ValidatingAdmissionPolicyBinding) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(operatorScopePolicyPath))
	if err != nil {
		t.Fatalf("read %s: %v", operatorScopePolicyPath, err)
	}
	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, string(raw), "ValidatingAdmissionPolicy", "confos-operator-scope", &vap) {
		t.Fatal("ValidatingAdmissionPolicy confos-operator-scope not in manifest")
	}
	var binding admissionregv1.ValidatingAdmissionPolicyBinding
	if !findDoc(t, string(raw), "ValidatingAdmissionPolicyBinding", "confos-operator-scope", &binding) {
		t.Fatal("ValidatingAdmissionPolicyBinding confos-operator-scope not in manifest")
	}
	return vap, binding
}

func TestOperatorScopePolicyShape(t *testing.T) {
	vap, binding := loadOperatorScopePolicy(t)
	if vap.Spec.FailurePolicy == nil || *vap.Spec.FailurePolicy != admissionregv1.Fail {
		t.Error("failurePolicy must be Fail so an evaluation error denies the write")
	}
	// Every group, resource and subresource, on every mutating operation:
	// the expression, not the match, decides what a c8s:* principal may do.
	var all, sub bool
	ops := map[admissionregv1.OperationType]bool{}
	for _, r := range vap.Spec.MatchConstraints.ResourceRules {
		for _, res := range r.Resources {
			all = all || res == "*"
			sub = sub || res == "*/*"
		}
		for _, op := range r.Operations {
			ops[op] = true
		}
	}
	if !all || !sub {
		t.Error("matchConstraints must name both \"*\" and \"*/*\" so subresources are covered")
	}
	for _, op := range []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update, admissionregv1.Delete, admissionregv1.Connect} {
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
	if binding.Spec.MatchResources != nil {
		t.Error("binding must not narrow the policy")
	}
	for _, v := range vap.Spec.Validations {
		if v.Message == "" {
			t.Errorf("validation %q has no message", v.Expression)
		}
	}
}

// scopeRequest models the AdmissionRequest fields the policy reads.
type scopeRequest struct {
	groups    []string
	namespace string
	group     string
	resource  string
	sub       string
}

// evalOperatorScope compiles every variable and validation and returns
// whether the request is admitted. Absent fields are left out of the map so
// has() sees exactly what the apiserver would present.
func evalOperatorScope(t *testing.T, vap admissionregv1.ValidatingAdmissionPolicy, r scopeRequest) bool {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("request", cel.DynType), cel.Variable("variables", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	userInfo := map[string]any{"username": "x"}
	if r.groups != nil {
		userInfo["groups"] = r.groups
	}
	req := map[string]any{
		"userInfo": userInfo,
		"resource": map[string]any{"group": r.group, "version": "v1", "resource": r.resource},
	}
	if r.namespace != "" {
		req["namespace"] = r.namespace
	}
	if r.sub != "" {
		req["subResource"] = r.sub
	}
	run := func(expr string, vars map[string]any) any {
		ast, iss := env.Compile(expr)
		if iss != nil && iss.Err() != nil {
			t.Fatalf("cel compile %q: %v", expr, iss.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := prg.Eval(map[string]any{"request": req, "variables": vars})
		if err != nil {
			t.Fatalf("cel eval %q: %v", expr, err)
		}
		return out.Value()
	}
	vars := map[string]any{}
	for _, v := range vap.Spec.Variables {
		vars[v.Name] = run(v.Expression, vars)
	}
	for _, v := range vap.Spec.Validations {
		if run(v.Expression, vars) != true {
			return false
		}
	}
	return true
}

func TestOperatorScopePolicyExpression(t *testing.T) {
	vap, _ := loadOperatorScopePolicy(t)
	op := []string{"system:authenticated", "c8s:node-operators"}
	logs := []string{"system:authenticated", "c8s:log-readers"}
	sys := []string{"system:authenticated", "system:masters"}
	for _, tc := range []struct {
		name string
		req  scopeRequest
		want bool
	}{
		// Other principals are never touched, whatever they write.
		{"system:masters in kube-system", scopeRequest{sys, "kube-system", "", "pods", ""}, true},
		{"system:masters clusterrolebinding", scopeRequest{sys, "", "rbac.authorization.k8s.io", "clusterrolebindings", ""}, true},
		{"no groups field at all", scopeRequest{nil, "kube-system", "", "pods", ""}, true},
		{"unrelated group in kube-system", scopeRequest{[]string{"tenants"}, "kube-system", "", "configmaps", ""}, true},
		// The operator's day-to-day work is admitted.
		{"operator pod in tenant ns", scopeRequest{op, "tenant", "", "pods", ""}, true},
		{"operator deployment in default", scopeRequest{op, "default", "apps", "deployments", ""}, true},
		{"operator namespace create", scopeRequest{op, "tenant", "", "namespaces", ""}, true},
		{"operator rolebinding in tenant ns", scopeRequest{op, "tenant", "rbac.authorization.k8s.io", "rolebindings", ""}, true},
		{"operator confidentialworkload", scopeRequest{op, "tenant", "confidential.ai", "confidentialworkloads", ""}, true},
		{"operator crd", scopeRequest{op, "", "apiextensions.k8s.io", "customresourcedefinitions", ""}, true},
		{"operator pod log (not proxy)", scopeRequest{op, "tenant", "", "pods", "log"}, true},
		// The guards and the host are out of reach.
		{"operator pod in kube-system", scopeRequest{op, "kube-system", "", "pods", ""}, false},
		{"operator configmap in local-path-storage", scopeRequest{op, "local-path-storage", "", "configmaps", ""}, false},
		{"operator secret in kube-system", scopeRequest{op, "kube-system", "", "secrets", ""}, false},
		{"operator token in kube-system", scopeRequest{op, "kube-system", "", "serviceaccounts", "token"}, false},
		{"operator delete kube-system namespace", scopeRequest{op, "kube-system", "", "namespaces", ""}, false},
		{"operator clusterrole", scopeRequest{op, "", "rbac.authorization.k8s.io", "clusterroles", ""}, false},
		{"operator clusterrolebinding", scopeRequest{op, "", "rbac.authorization.k8s.io", "clusterrolebindings", ""}, false},
		{"operator vap", scopeRequest{op, "", "admissionregistration.k8s.io", "validatingadmissionpolicies", ""}, false},
		{"operator vap binding", scopeRequest{op, "", "admissionregistration.k8s.io", "validatingadmissionpolicybindings", ""}, false},
		{"operator mutating webhook", scopeRequest{op, "", "admissionregistration.k8s.io", "mutatingwebhookconfigurations", ""}, false},
		{"operator helmchart in tenant ns", scopeRequest{op, "tenant", "helm.cattle.io", "helmcharts", ""}, false},
		{"operator k3s addon", scopeRequest{op, "kube-system", "k3s.cattle.io", "addons", ""}, false},
		{"operator storageclass", scopeRequest{op, "", "storage.k8s.io", "storageclasses", ""}, false},
		{"operator persistentvolume", scopeRequest{op, "", "", "persistentvolumes", ""}, false},
		{"operator node", scopeRequest{op, "", "", "nodes", ""}, false},
		{"operator node status", scopeRequest{op, "", "", "nodes", "status"}, false},
		{"operator apiservice", scopeRequest{op, "", "apiregistration.k8s.io", "apiservices", ""}, false},
		{"operator csr approval", scopeRequest{op, "", "certificates.k8s.io", "certificatesigningrequests", "approval"}, false},
		{"operator nodes/proxy", scopeRequest{op, "", "", "nodes", "proxy"}, false},
		{"operator pods/proxy", scopeRequest{op, "tenant", "", "pods", "proxy"}, false},
		{"operator services/proxy", scopeRequest{op, "tenant", "", "services", "proxy"}, false},
		// The log-reader is a c8s:* group too.
		{"log-reader configmap in kube-system", scopeRequest{logs, "kube-system", "", "configmaps", ""}, false},
		{"log-reader clusterrolebinding", scopeRequest{logs, "", "rbac.authorization.k8s.io", "clusterrolebindings", ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalOperatorScope(t, vap, tc.req); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}
