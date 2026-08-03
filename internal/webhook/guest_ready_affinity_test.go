package webhook

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// guestReadyExprs returns the guest-ready requirement from every term it
// appears in.
func guestReadyExprs(pod *corev1.Pod) []corev1.NodeSelectorRequirement {
	var out []corev1.NodeSelectorRequirement
	if pod.Spec.Affinity == nil || pod.Spec.Affinity.NodeAffinity == nil {
		return out
	}
	req := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	if req == nil {
		return out
	}
	for _, term := range req.NodeSelectorTerms {
		for _, e := range term.MatchExpressions {
			if e.Key == GuestReadyNodeLabel {
				out = append(out, e)
			}
		}
	}
	return out
}

func TestRequireGuestReadyNodeOnBarePod(t *testing.T) {
	pod := &corev1.Pod{}
	requireGuestReadyNode(pod)

	got := guestReadyExprs(pod)
	if len(got) != 1 {
		t.Fatalf("guest-ready requirements = %d, want 1", len(got))
	}
	if got[0].Operator != corev1.NodeSelectorOpIn || len(got[0].Values) != 1 || got[0].Values[0] != "true" {
		t.Fatalf("requirement = %+v, want In [true]", got[0])
	}
}

// Terms are OR-ed, so the gate must land in every one of them.
func TestRequireGuestReadyNodeAndsWithEveryExistingTerm(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Affinity: &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"},
					}}},
					{MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"b"},
					}}},
				},
			},
		},
	}}}
	requireGuestReadyNode(pod)

	terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) != 2 {
		t.Fatalf("nodeSelectorTerms = %d, want the original 2 (a new term would OR away the gate)", len(terms))
	}
	for i, term := range terms {
		var found bool
		for _, e := range term.MatchExpressions {
			if e.Key == GuestReadyNodeLabel {
				found = true
			}
		}
		if !found {
			t.Fatalf("term %d has no guest-ready requirement; the gate is satisfiable without it", i)
		}
	}
}

// reinvocationPolicy: IfNeeded — a second pass must not stack the expression.
func TestRequireGuestReadyNodeIsIdempotent(t *testing.T) {
	pod := &corev1.Pod{}
	requireGuestReadyNode(pod)
	requireGuestReadyNode(pod)

	if got := guestReadyExprs(pod); len(got) != 1 {
		t.Fatalf("guest-ready requirements after two passes = %d, want 1", len(got))
	}
}

func TestRequireGuestReadyNodePreservesUnrelatedAffinity(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Affinity: &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{},
		NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{{Weight: 1}},
		},
	}}}
	requireGuestReadyNode(pod)

	if pod.Spec.Affinity.PodAntiAffinity == nil {
		t.Fatal("podAntiAffinity was dropped")
	}
	if len(pod.Spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatal("preferred node affinity was dropped")
	}
	if len(guestReadyExprs(pod)) != 1 {
		t.Fatal("guest-ready requirement missing")
	}
}
