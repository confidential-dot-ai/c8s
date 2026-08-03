package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

const kataImagePullerComponent = "kata-image-puller"

const componentLabel = "app.kubernetes.io/component"

// KataGuestReadyReconciler maintains webhook.GuestReadyNodeLabel from the
// node's kata-image-puller readiness, which already re-validates the drop-in
// fingerprint and the pulled artifacts. Mirroring it keeps one source of truth.
//
// Keyed on Node, not Pod, so a deleted puller pod still clears the label.
type KataGuestReadyReconciler struct {
	client.Client

	// Namespace is the release namespace holding the puller DaemonSet.
	Namespace string
}

func (r *KataGuestReadyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var node corev1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get node %s: %w", req.Name, err)
	}

	ready, err := r.pullerReadyOn(ctx, node.Name)
	if err != nil {
		return ctrl.Result{}, err
	}

	_, labelled := node.Labels[webhook.GuestReadyNodeLabel]
	want := "true"
	if ready && node.Labels[webhook.GuestReadyNodeLabel] == want {
		return ctrl.Result{}, nil
	}
	if !ready && !labelled {
		return ctrl.Result{}, nil
	}

	patch := client.MergeFrom(node.DeepCopy())
	if ready {
		if node.Labels == nil {
			node.Labels = map[string]string{}
		}
		node.Labels[webhook.GuestReadyNodeLabel] = want
	} else {
		delete(node.Labels, webhook.GuestReadyNodeLabel)
	}
	if err := r.Patch(ctx, &node, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch node %s: %w", node.Name, err)
	}
	l.Info("kata guest readiness changed", "node", node.Name, "ready", ready)
	return ctrl.Result{}, nil
}

// pullerReadyOn reports whether a Ready puller pod is running on node. Absent,
// pending and terminating all read as not ready.
func (r *KataGuestReadyReconciler) pullerReadyOn(ctx context.Context, node string) (bool, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods,
		client.InNamespace(r.Namespace),
		client.MatchingLabels{componentLabel: kataImagePullerComponent},
	); err != nil {
		return false, fmt.Errorf("list kata-image-puller pods: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName != node || pod.DeletionTimestamp != nil {
			continue
		}
		if isPodReady(pod) {
			return true, nil
		}
	}
	return false, nil
}

func (r *KataGuestReadyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(pullerPodToNode),
			builder.WithPredicates(pullerPodPredicate(r.Namespace)),
		).
		Named("kata-guest-ready").
		Complete(r)
}

// pullerPodToNode maps a puller pod event onto its node.
func pullerPodToNode(_ context.Context, obj client.Object) []ctrl.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.NodeName == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: client.ObjectKey{Name: pod.Spec.NodeName}}}
}

// pullerPodPredicate keeps the shared Pod informer from waking this controller
// for every pod in the cluster.
func pullerPodPredicate(namespace string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetNamespace() == namespace &&
			obj.GetLabels()[componentLabel] == kataImagePullerComponent
	})
}
