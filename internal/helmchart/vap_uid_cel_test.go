// Behaviorally evaluates the rendered deny-ratls-mesh-uid and
// deny-ratls-mesh-uid-ephemeral ValidatingAdmissionPolicies with cel-go over
// the same expressions the apiserver compiles, so UID-0 / reserved-proxy-UID
// admission is tested, not just rendered.
//
// The expressions are compiled over `object: dyn`: the apiserver type-checks
// VAP expressions against the matched resource schema, which cel-go cannot
// reproduce here; evaluating over dyn still exercises the guards (runAsUser 0
// and the reserved proxy UID) that the policies must enforce. A live
// `kubectl apply` of the policy remains the schema-level proof (see the PR
// body's live-e2e list).
package helmchart

import (
	"testing"

	"github.com/google/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// renderedUIDPolicies renders the chart and pulls both UID admission policies'
// validation expressions, keyed by policy name.
func renderedUIDPolicies(t *testing.T) map[string][]admissionregv1.Validation {
	t.Helper()
	out, err := helmTemplate(t, chartNodeMetal)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	policies := map[string][]admissionregv1.Validation{}
	iterateManifests(t, out, func(doc []byte) bool {
		var p admissionregv1.ValidatingAdmissionPolicy
		if err := sigsyaml.Unmarshal(doc, &p); err != nil {
			return false
		}
		if p.Kind != "ValidatingAdmissionPolicy" {
			return false
		}
		policies[p.Name] = p.Spec.Validations
		return false
	})
	for _, name := range []string{"deny-ratls-mesh-uid", "deny-ratls-mesh-uid-ephemeral"} {
		if _, ok := policies[name]; !ok {
			t.Fatalf("%s policy not rendered", name)
		}
	}
	return policies
}

// evalPolicy compiles one validation expression against an admission `object`
// and reports whether it evaluates to true (allowed) without error.
func evalPolicy(t *testing.T, expr string, object map[string]any) bool {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("object", cel.DynType))
	if err != nil {
		t.Fatalf("cel env: %v", err)
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("cel compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("cel program: %v", err)
	}
	out, _, err := prg.Eval(map[string]any{"object": object})
	if err != nil {
		t.Fatalf("cel eval %q: %v", expr, err)
	}
	return out.Value() == true
}

// allTrue asserts every validation of a policy allows the object.
func allTrue(t *testing.T, validations []admissionregv1.Validation, o map[string]any) {
	t.Helper()
	for _, v := range validations {
		if !evalPolicy(t, v.Expression, o) {
			t.Errorf("expression %q denied an object that should be allowed", v.Expression)
		}
	}
}

// anyFalse asserts at least one validation denies the object.
func anyFalse(t *testing.T, validations []admissionregv1.Validation, o map[string]any) {
	t.Helper()
	for _, v := range validations {
		if !evalPolicy(t, v.Expression, o) {
			return
		}
	}
	t.Errorf("policy admitted an object that every expression allowed")
}

// container shapes a container map with an optional runAsUser (int64 so CEL
// sees an int, never a double).
func container(name, image string, runAsUser *int64) map[string]any {
	c := map[string]any{"name": name, "image": image}
	if runAsUser != nil {
		c["securityContext"] = map[string]any{"runAsUser": *runAsUser}
	}
	return c
}

func TestDenyRATLSMeshUidPodPolicyBehaviors(t *testing.T) {
	policies := renderedUIDPolicies(t)
	validations := policies["deny-ratls-mesh-uid"]

	u1000 := int64(1000)
	u0 := int64(0)
	u1337 := int64(1337)

	// A pod with no securityContext is allowed.
	allTrue(t, validations, map[string]any{
		"spec": map[string]any{"containers": []any{container("app", "busybox", nil)}},
	})

	// Pod-level runAsUser 0 is not in any exemption cgroup -> denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"securityContext": map[string]any{"runAsUser": u0}},
	})

	// Pod-level runAsUser 1337 is the proxy's reserved UID -> denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"securityContext": map[string]any{"runAsUser": u1337}},
	})

	// A non-reserved, non-0 user is allowed.
	allTrue(t, validations, map[string]any{
		"spec": map[string]any{"securityContext": map[string]any{"runAsUser": u1000}},
	})

	// A container requesting runAsUser 0 is denied even with no pod context.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"containers": []any{container("app", "busybox", &u0)}},
	})

	// An init container at UID 0 is denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{
			"initContainers": []any{container("init", "busybox", &u0)},
			"containers":     []any{container("app", "busybox", nil)},
		},
	})
}

func TestDenyRATLSMeshUidEphemeralPolicyBehaviors(t *testing.T) {
	policies := renderedUIDPolicies(t)
	validations := policies["deny-ratls-mesh-uid-ephemeral"]

	u1000 := int64(1000)
	u0 := int64(0)

	// The pods/ephemeralcontainers subresource with no shape is allowed.
	allTrue(t, validations, map[string]any{"spec": map[string]any{}})

	// An ephemeral container at UID 0 is denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"ephemeralContainers": []any{container("debugger", "busybox", &u0)}},
	})

	// An ephemeral container at a non-reserved user is allowed.
	allTrue(t, validations, map[string]any{
		"spec": map[string]any{"ephemeralContainers": []any{container("debugger", "busybox", &u1000)}},
	})
}
