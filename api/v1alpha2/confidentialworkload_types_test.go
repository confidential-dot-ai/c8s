package v1alpha2

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// fullCW returns a ConfidentialWorkload with every field populated, including
// non-nil slices, maps, and pointers, so deep-copy round-trips exercise every
// branch of the generated DeepCopy functions.
func fullCW() *ConfidentialWorkload {
	return &ConfidentialWorkload{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfidentialWorkload",
			APIVersion: "confidential.ai/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "cw-1",
			Namespace:   "default",
			Labels:      map[string]string{"app": "demo"},
			Annotations: map[string]string{"k": "v"},
			Finalizers:  []string{"confidential.ai/finalizer"},
		},
		Spec: ConfidentialWorkloadSpec{
			WorkloadRef: WorkloadRef{
				Kind: WorkloadKindDeployment,
				Name: "my-deploy",
			},
		},
		Status: ConfidentialWorkloadStatus{
			Conditions: []metav1.Condition{
				{
					Type:               ConditionAttested,
					Status:             metav1.ConditionTrue,
					Reason:             "AllPodsAttested",
					Message:            "ok",
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:   ConditionCertIssued,
					Status: metav1.ConditionFalse,
					Reason: "Pending",
				},
			},
			AttestationSummary: &AttestationSummary{Total: 3, Attested: 2},
			ObservedGeneration: 7,
		},
	}
}

func TestConfidentialWorkload_DeepCopy_RoundTrip(t *testing.T) {
	orig := fullCW()
	cp := orig.DeepCopy()

	if !reflect.DeepEqual(orig, cp) {
		t.Fatalf("DeepCopy not equal to original\norig: %#v\ncopy: %#v", orig, cp)
	}

	// Mutate the copy; the original must be untouched.
	cp.Labels["app"] = "changed"
	cp.Annotations["k"] = "changed"
	cp.Finalizers[0] = "changed"
	cp.Spec.WorkloadRef.Name = "changed"
	cp.Status.Conditions[0].Reason = "changed"
	cp.Status.AttestationSummary.Attested = 99
	cp.Status.ObservedGeneration = 99

	if orig.Labels["app"] != "demo" {
		t.Errorf("mutating copy Labels affected original: %q", orig.Labels["app"])
	}
	if orig.Annotations["k"] != "v" {
		t.Errorf("mutating copy Annotations affected original: %q", orig.Annotations["k"])
	}
	if orig.Finalizers[0] != "confidential.ai/finalizer" {
		t.Errorf("mutating copy Finalizers affected original: %q", orig.Finalizers[0])
	}
	if orig.Spec.WorkloadRef.Name != "my-deploy" {
		t.Errorf("mutating copy Spec affected original: %q", orig.Spec.WorkloadRef.Name)
	}
	if orig.Status.Conditions[0].Reason != "AllPodsAttested" {
		t.Errorf("mutating copy Conditions affected original: %q", orig.Status.Conditions[0].Reason)
	}
	if orig.Status.AttestationSummary.Attested != 2 {
		t.Errorf("mutating copy AttestationSummary affected original: %d", orig.Status.AttestationSummary.Attested)
	}
	if orig.Status.ObservedGeneration != 7 {
		t.Errorf("mutating copy ObservedGeneration affected original: %d", orig.Status.ObservedGeneration)
	}

	// AttestationSummary must be a distinct pointer.
	if orig.Status.AttestationSummary == cp.Status.AttestationSummary {
		t.Error("AttestationSummary pointer shared between original and copy")
	}
}

func TestConfidentialWorkload_DeepCopy_Nil(t *testing.T) {
	var nilCW *ConfidentialWorkload
	if nilCW.DeepCopy() != nil {
		t.Error("DeepCopy of nil ConfidentialWorkload should be nil")
	}
}

func TestConfidentialWorkload_DeepCopyObject(t *testing.T) {
	orig := fullCW()
	obj := orig.DeepCopyObject()
	cp, ok := obj.(*ConfidentialWorkload)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, want *ConfidentialWorkload", obj)
	}
	if !reflect.DeepEqual(orig, cp) {
		t.Error("DeepCopyObject not equal to original")
	}

	var nilCW *ConfidentialWorkload
	if got := nilCW.DeepCopyObject(); got != nil {
		t.Errorf("DeepCopyObject of nil should be nil, got %#v", got)
	}
}

func TestConfidentialWorkloadList_DeepCopy_RoundTrip(t *testing.T) {
	orig := &ConfidentialWorkloadList{
		TypeMeta: metav1.TypeMeta{Kind: "ConfidentialWorkloadList", APIVersion: "confidential.ai/v1alpha2"},
		ListMeta: metav1.ListMeta{ResourceVersion: "42", Continue: "next"},
		Items:    []ConfidentialWorkload{*fullCW(), *fullCW()},
	}
	cp := orig.DeepCopy()

	if !reflect.DeepEqual(orig, cp) {
		t.Fatal("List DeepCopy not equal to original")
	}

	cp.Items[0].Spec.WorkloadRef.Name = "changed"
	if orig.Items[0].Spec.WorkloadRef.Name != "my-deploy" {
		t.Errorf("mutating copy Items affected original: %q", orig.Items[0].Spec.WorkloadRef.Name)
	}
	cp.ResourceVersion = "99"
	if orig.ResourceVersion != "42" {
		t.Errorf("mutating copy ListMeta affected original: %q", orig.ResourceVersion)
	}
}

func TestConfidentialWorkloadList_DeepCopy_Nil(t *testing.T) {
	var nilList *ConfidentialWorkloadList
	if nilList.DeepCopy() != nil {
		t.Error("DeepCopy of nil ConfidentialWorkloadList should be nil")
	}
}

func TestConfidentialWorkloadList_DeepCopyObject(t *testing.T) {
	orig := &ConfidentialWorkloadList{
		Items: []ConfidentialWorkload{*fullCW()},
	}
	obj := orig.DeepCopyObject()
	cp, ok := obj.(*ConfidentialWorkloadList)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, want *ConfidentialWorkloadList", obj)
	}
	if !reflect.DeepEqual(orig, cp) {
		t.Error("List DeepCopyObject not equal to original")
	}

	// Nil Items branch.
	empty := &ConfidentialWorkloadList{}
	if !reflect.DeepEqual(empty, empty.DeepCopy()) {
		t.Error("empty List DeepCopy not equal to original")
	}

	var nilList *ConfidentialWorkloadList
	if got := nilList.DeepCopyObject(); got != nil {
		t.Errorf("DeepCopyObject of nil List should be nil, got %#v", got)
	}
}

func TestConfidentialWorkloadSpec_DeepCopy(t *testing.T) {
	orig := &ConfidentialWorkloadSpec{WorkloadRef: WorkloadRef{Kind: WorkloadKindStatefulSet, Name: "ss"}}
	cp := orig.DeepCopy()
	if !reflect.DeepEqual(orig, cp) {
		t.Error("Spec DeepCopy not equal to original")
	}
	cp.WorkloadRef.Name = "changed"
	if orig.WorkloadRef.Name != "ss" {
		t.Error("mutating Spec copy affected original")
	}

	var nilSpec *ConfidentialWorkloadSpec
	if nilSpec.DeepCopy() != nil {
		t.Error("DeepCopy of nil Spec should be nil")
	}
}

func TestConfidentialWorkloadStatus_DeepCopy(t *testing.T) {
	orig := &ConfidentialWorkloadStatus{
		Conditions:         []metav1.Condition{{Type: ConditionAttested, Status: metav1.ConditionTrue}},
		AttestationSummary: &AttestationSummary{Total: 1, Attested: 1},
		ObservedGeneration: 5,
	}
	cp := orig.DeepCopy()
	if !reflect.DeepEqual(orig, cp) {
		t.Error("Status DeepCopy not equal to original")
	}
	cp.Conditions[0].Type = "changed"
	cp.AttestationSummary.Total = 99
	if orig.Conditions[0].Type != ConditionAttested {
		t.Error("mutating Status Conditions copy affected original")
	}
	if orig.AttestationSummary.Total != 1 {
		t.Error("mutating Status AttestationSummary copy affected original")
	}
	if orig.AttestationSummary == cp.AttestationSummary {
		t.Error("AttestationSummary pointer shared")
	}

	// Empty status: nil Conditions and nil AttestationSummary branches.
	empty := &ConfidentialWorkloadStatus{}
	if !reflect.DeepEqual(empty, empty.DeepCopy()) {
		t.Error("empty Status DeepCopy not equal to original")
	}

	var nilStatus *ConfidentialWorkloadStatus
	if nilStatus.DeepCopy() != nil {
		t.Error("DeepCopy of nil Status should be nil")
	}
}

func TestAttestationSummary_DeepCopy(t *testing.T) {
	orig := &AttestationSummary{Total: 4, Attested: 3}
	cp := orig.DeepCopy()
	if !reflect.DeepEqual(orig, cp) {
		t.Error("AttestationSummary DeepCopy not equal to original")
	}
	cp.Attested = 0
	if orig.Attested != 3 {
		t.Error("mutating AttestationSummary copy affected original")
	}
	if orig == cp {
		t.Error("AttestationSummary DeepCopy returned same pointer")
	}

	var nilAS *AttestationSummary
	if nilAS.DeepCopy() != nil {
		t.Error("DeepCopy of nil AttestationSummary should be nil")
	}
}

func TestWorkloadRef_DeepCopy(t *testing.T) {
	orig := &WorkloadRef{Kind: WorkloadKindDaemonSet, Name: "ds"}
	cp := orig.DeepCopy()
	if !reflect.DeepEqual(orig, cp) {
		t.Error("WorkloadRef DeepCopy not equal to original")
	}
	cp.Name = "changed"
	if orig.Name != "ds" {
		t.Error("mutating WorkloadRef copy affected original")
	}

	var nilRef *WorkloadRef
	if nilRef.DeepCopy() != nil {
		t.Error("DeepCopy of nil WorkloadRef should be nil")
	}
}

func TestAddToScheme(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}

	for _, obj := range []runtime.Object{&ConfidentialWorkload{}, &ConfidentialWorkloadList{}} {
		gvks, _, err := s.ObjectKinds(obj)
		if err != nil {
			t.Errorf("ObjectKinds(%T) failed: %v", obj, err)
			continue
		}
		var found bool
		for _, gvk := range gvks {
			if gvk.Group == GroupVersion.Group && gvk.Version == GroupVersion.Version {
				found = true
			}
		}
		if !found {
			t.Errorf("%T not registered under %s", obj, GroupVersion)
		}
	}
}
