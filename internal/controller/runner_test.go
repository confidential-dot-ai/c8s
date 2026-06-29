package controller

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1alpha2 "github.com/confidential-dot-ai/c8s/api/v1alpha2"
)

type fakeServerResources struct {
	resources *metav1.APIResourceList
	err       error
	gotGV     string
}

func (f *fakeServerResources) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	f.gotGV = groupVersion
	return f.resources, f.err
}

func TestConfidentialWorkloadCRDAvailable(t *testing.T) {
	tests := []struct {
		name      string
		resources *metav1.APIResourceList
		err       error
		want      bool
		wantErr   bool
	}{
		{
			name: "available",
			resources: &metav1.APIResourceList{APIResources: []metav1.APIResource{
				{Name: "confidentialworkloads", Kind: "ConfidentialWorkload"},
			}},
			want: true,
		},
		{
			name:      "nil resource list with no error",
			resources: nil,
			want:      false,
		},
		{
			name: "group version not found",
			err: apierrors.NewNotFound(schema.GroupResource{
				Group:    v1alpha2.GroupVersion.Group,
				Resource: "confidentialworkloads",
			}, ""),
			want: false,
		},
		{
			name: "resource missing from group version",
			resources: &metav1.APIResourceList{APIResources: []metav1.APIResource{
				{Name: "pods", Kind: "Pod"},
			}},
			want: false,
		},
		{
			name:    "discovery error",
			err:     errors.New("discovery failed"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeServerResources{resources: tt.resources, err: tt.err}
			got, err := confidentialWorkloadCRDAvailable(fake)
			if tt.wantErr {
				if err == nil {
					t.Fatal("confidentialWorkloadCRDAvailable returned nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("confidentialWorkloadCRDAvailable returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("confidentialWorkloadCRDAvailable = %v, want %v", got, tt.want)
			}
			if fake.gotGV != v1alpha2.GroupVersion.String() {
				t.Fatalf("discovered groupVersion %q, want %q", fake.gotGV, v1alpha2.GroupVersion.String())
			}
		})
	}
}

func TestBoolPtr(t *testing.T) {
	for _, v := range []bool{true, false} {
		p := boolPtr(v)
		if p == nil || *p != v {
			t.Fatalf("boolPtr(%v) = %v", v, p)
		}
	}
}

func TestInt64Ptr(t *testing.T) {
	for _, v := range []int64{0, -1, 1000} {
		p := int64Ptr(v)
		if p == nil || *p != v {
			t.Fatalf("int64Ptr(%d) = %v", v, p)
		}
	}
}
