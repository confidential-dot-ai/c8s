package getkubeconfig

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func vmiWithStatus(status map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "kubevirt.io/v1",
		"kind":       "VirtualMachineInstance",
		"metadata": map[string]any{
			"name":      "mn-server",
			"namespace": "confai-images",
		},
	}
	if status != nil {
		obj["status"] = status
	}
	return &unstructured.Unstructured{Object: obj}
}

func TestVMIAddress(t *testing.T) {
	cases := []struct {
		name    string
		status  map[string]any
		want    string
		wantErr string
	}{
		{
			name: "first interface wins",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": "10.42.0.158"},
				map[string]any{"ipAddress": "10.42.0.201"},
			}},
			want: "10.42.0.158",
		},
		{
			// A booting guest can report an interface before its address.
			name: "address-less interface is skipped",
			status: map[string]any{"interfaces": []any{
				map[string]any{"name": "default"},
				map[string]any{"ipAddress": "10.42.0.201"},
			}},
			want: "10.42.0.201",
		},
		{
			name:    "no status",
			status:  nil,
			wantErr: "no reported address",
		},
		{
			name:    "empty interfaces",
			status:  map[string]any{"interfaces": []any{}},
			wantErr: "no reported address",
		},
		{
			name: "empty ipAddress",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": ""},
			}},
			wantErr: "no reported address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vmiAddress(vmiWithStatus(tc.status))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("vmiAddress: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestResolveVMIRejectsMalformedRefs(t *testing.T) {
	// Ref validation runs before any kubeconfig or cluster access, so these
	// fail fast with the ref error regardless of the test environment.
	for _, ref := range []string{"", "/mn-server", "confai-images/", "/"} {
		if _, err := resolveVMI(context.Background(), ref); err == nil ||
			!strings.Contains(err.Error(), "is not name or namespace/name") {
			t.Fatalf("ref %q: want malformed-ref error, got %v", ref, err)
		}
	}
}
