package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

const testReleaseNS = "c8s-system"

func guestReadyNode(name string, labelled bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if labelled {
		n.Labels[webhook.GuestReadyNodeLabel] = "true"
	}
	return n
}

func pullerPod(name, node string, ready bool) *corev1.Pod {
	cond := corev1.ConditionFalse
	if ready {
		cond = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testReleaseNS,
			Labels:    map[string]string{ComponentLabel: KataImagePullerComponent},
		},
		Spec: corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: cond}},
		},
	}
}

func reconcileNode(t *testing.T, objs []client.Object, node string) *corev1.Node {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	r := &KataGuestReadyReconciler{Client: c, Namespace: testReleaseNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Name: node},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got corev1.Node
	if err := c.Get(context.Background(), client.ObjectKey{Name: node}, &got); err != nil {
		t.Fatalf("get node: %v", err)
	}
	return &got
}

func TestGuestReadyLabelAppliedWhenPullerReady(t *testing.T) {
	got := reconcileNode(t, []client.Object{
		guestReadyNode("n1", false),
		pullerPod("puller-n1", "n1", true),
	}, "n1")

	if got.Labels[webhook.GuestReadyNodeLabel] != "true" {
		t.Fatalf("label = %q, want true — a ready puller means the node resolves the c8s guest",
			got.Labels[webhook.GuestReadyNodeLabel])
	}
}

// A regressed puller (values changed, drop-in stale) must clear the label.
func TestGuestReadyLabelRemovedWhenPullerNotReady(t *testing.T) {
	got := reconcileNode(t, []client.Object{
		guestReadyNode("n1", true),
		pullerPod("puller-n1", "n1", false),
	}, "n1")

	if _, ok := got.Labels[webhook.GuestReadyNodeLabel]; ok {
		t.Fatal("label still present after the puller went unready")
	}
}

func TestGuestReadyLabelRemovedWhenPullerAbsent(t *testing.T) {
	got := reconcileNode(t, []client.Object{guestReadyNode("n1", true)}, "n1")

	if _, ok := got.Labels[webhook.GuestReadyNodeLabel]; ok {
		t.Fatal("label still present with no puller pod on the node")
	}
}

// A ready puller on a different node says nothing about this one.
func TestGuestReadyLabelIsPerNode(t *testing.T) {
	got := reconcileNode(t, []client.Object{
		guestReadyNode("n1", false),
		guestReadyNode("n2", false),
		pullerPod("puller-n2", "n2", true),
	}, "n1")

	if _, ok := got.Labels[webhook.GuestReadyNodeLabel]; ok {
		t.Fatal("n1 labelled from a puller running on n2")
	}
}

// A terminating pod reports Ready until it is gone, which would hold the gate
// open across the rollout replacing it.
func TestGuestReadyLabelIgnoresTerminatingPuller(t *testing.T) {
	pod := pullerPod("puller-n1", "n1", true)
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	pod.Finalizers = []string{"c8s.test/hold"}

	got := reconcileNode(t, []client.Object{guestReadyNode("n1", true), pod}, "n1")

	if _, ok := got.Labels[webhook.GuestReadyNodeLabel]; ok {
		t.Fatal("label held open by a terminating puller pod")
	}
}

// The component label is not namespaced; the release namespace is the guard.
func TestGuestReadyLabelIgnoresForeignNamespace(t *testing.T) {
	pod := pullerPod("puller-n1", "n1", true)
	pod.Namespace = "attacker"

	got := reconcileNode(t, []client.Object{guestReadyNode("n1", false), pod}, "n1")

	if _, ok := got.Labels[webhook.GuestReadyNodeLabel]; ok {
		t.Fatal("node labelled from a puller-labelled pod outside the release namespace")
	}
}

func TestGuestReadyReconcileMissingNodeIsNoop(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &KataGuestReadyReconciler{Client: c, Namespace: testReleaseNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Name: "gone"},
	}); err != nil {
		t.Fatalf("Reconcile on a deleted node: %v", err)
	}
}

func TestPullerPodToNode(t *testing.T) {
	reqs := pullerPodToNode(context.Background(), pullerPod("p", "n1", true))
	if len(reqs) != 1 || reqs[0].Name != "n1" {
		t.Fatalf("pullerPodToNode = %+v, want one request for n1", reqs)
	}
	if got := pullerPodToNode(context.Background(), pullerPod("p", "", true)); len(got) != 0 {
		t.Fatalf("unscheduled pod produced %d requests, want 0", len(got))
	}
}

func TestPullerPodPredicate(t *testing.T) {
	p := pullerPodPredicate(testReleaseNS)
	if !p.Create(event.CreateEvent{Object: pullerPod("p", "n1", true)}) {
		t.Fatal("predicate rejected a puller pod in the release namespace")
	}
	other := pullerPod("p", "n1", true)
	other.Labels[ComponentLabel] = "cds"
	if p.Create(event.CreateEvent{Object: other}) {
		t.Fatal("predicate accepted a non-puller pod")
	}
}
